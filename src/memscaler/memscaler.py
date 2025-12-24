import ctypes as ct
import logging
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from socket import AF_INET, AF_INET6, inet_ntop
from time import perf_counter

from bcc import BPF
from rich.logging import RichHandler

from .types import TCP_STATE, TCP_STATES_CLOSE, TCP_STATES_OPEN, IPv4Event, IPv6Event

# config
MONITORED_PORT = 5001
IPV4_ONLY = False

TARGET_GPUS = [0, 1]
IDLE_MEMORY_CLOCK_MHZ = 405
IDLE_TIMEOUT_SEC = 60
LOG_INTERVAL_SEC = 30

# if you're using a HWE kernel on ubuntu and you don't go recompile bpfcc yourself,
# you'll get some macro errors from the kernel headers. they don't matter for our purposes,
# so just suppress them.
BPF_CFLAGS = ["-Wno-macro-redefined"]

# setup logging
logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(omit_repeated_times=False)],
    format="%(message)s",
    datefmt="[%x %X.%f]",
)
logger = logging.getLogger("memscaler")


# ---- synchronization primitives ----
idle_flag = threading.Event()  # set when GPUs are in idle mode
shutdown_evt = threading.Event()  # set when program is shutting down
transition_q = queue.Queue()  # queue for GPU mode transitions
lock = threading.Lock()

# ---- global state ----
active_count = 0
last_log = 0


# ---- GPU management functions ----
def set_gpu_performance_mode(
    target_gpus: list[int | str] | None = None,
    force: bool = False,
):
    global idle_flag, shutdown_evt
    try:
        target_args = []
        target_str = "all GPUs"

        if target_gpus is None:
            target_gpus = TARGET_GPUS
            target_args = ["-i", ",".join(map(str, target_gpus))] if target_gpus else []
            target_str = "GPUs " + target_args[1] if target_gpus else target_str

        if force or idle_flag.is_set():
            result = subprocess.check_output(
                ["/usr/bin/nvidia-smi", *target_args, "-rmc"],
                encoding="utf-8",
            )
            for line in result.splitlines():
                logger.debug(f"nvidia-smi: {line}")
            logger.info(f"Reset {target_str} to performance mode (memory clock auto)")
            idle_flag.clear()
        else:
            logger.info(f"{target_str} already in performance mode")
    except subprocess.CalledProcessError:
        logger.exception("Failed to set GPU performance mode")


def set_gpu_idle_mode(
    target_gpus: list[int | str] | None = None,
    lmc: int | str = IDLE_MEMORY_CLOCK_MHZ,
    force: bool = False,
):
    global idle_flag, shutdown_evt
    try:
        target_args = []
        target_str = "all GPUs"

        if target_gpus is None:
            target_gpus = TARGET_GPUS
            target_args = ["-i", ",".join(map(str, target_gpus))] if target_gpus else []
            target_str = "GPUs " + target_args[1] if target_gpus else target_str

        if force or (not idle_flag.is_set()):
            result = subprocess.check_output(
                ["/usr/bin/nvidia-smi", *target_args, "-lmc", str(lmc)],
                encoding="utf-8",
            )
            for line in result.splitlines():
                logger.debug(f"nvidia-smi: {line}")
            logger.info(f"Set {target_str} to idle mode (memory clock {lmc} MHz)")
            idle_flag.set()
        else:
            logger.info(f"{target_str} already in idle mode")
    except subprocess.CalledProcessError:
        logger.exception("Failed to set GPU idle mode")


# ---- worker thread ----


def gpu_worker_func(
    shutdown_evt: threading.Event,
    transition_q: queue.Queue,
):
    def prepare_idle_timer(last_timer: threading.Timer | None = None) -> threading.Timer:
        if last_timer and last_timer.is_alive():
            last_timer.cancel()
            last_timer.join()
        thread = threading.Timer(
            IDLE_TIMEOUT_SEC,
            function=set_gpu_idle_mode,
            kwargs={"target_gpus": TARGET_GPUS},
        )
        return thread

    idle_timer = prepare_idle_timer()

    while True:
        try:
            transition = transition_q.get(timeout=1)
            if transition == "active":
                logger.info("Got ACTIVE transition")
                if idle_timer and idle_timer.is_alive():
                    idle_timer.cancel()
                    idle_timer.join()
                    logger.info("Cancelled idle timer")
                set_gpu_performance_mode()

            elif transition == "idle":
                logger.info("Got IDLE transition")
                if not idle_timer.is_alive():
                    idle_timer = prepare_idle_timer(idle_timer)
                    idle_timer.start()
                    logger.info(f"Will idle in {IDLE_TIMEOUT_SEC} seconds")

            elif transition == "idle-now":
                logger.info("Got IDLE-NOW transition")
                if idle_timer and idle_timer.is_alive():
                    idle_timer.cancel()
                    idle_timer.join()
                    logger.info("Cancelled idle timer")
                set_gpu_idle_mode(force=True)
            else:
                logger.error(f"Unknown transition received in GPU worker thread: {transition}")
        except queue.Empty:
            pass
        except Exception:
            logger.exception("Exception in GPU worker thread")

        if shutdown_evt.is_set():
            logger.debug("Shutdown event set, exiting GPU worker thread")
            if idle_timer and idle_timer.is_alive():
                idle_timer.cancel()
                idle_timer.join()
                logger.debug("Cancelled idle timer on shutdown")
            return


# ---- BPF event handler ----
def sock_inet_set_state_cb(cpu, data, size, family: int):
    global active_count, last_log, lock
    if family == AF_INET:
        logger.debug(f"Received IPv4 event from CPU {cpu}")
        ev = ct.cast(data, ct.POINTER(IPv4Event)).contents
    elif family == AF_INET6:
        logger.debug(f"Received IPv6 event from CPU {cpu}")
        ev = ct.cast(data, ct.POINTER(IPv6Event)).contents
    else:
        logger.error(f"Unknown address family in BPF event: {family}")
        return

    saddr = inet_ntop(family, bytes(ev.saddr))
    dport = int(ev.dport)
    oldstate = TCP_STATE(int(ev.oldstate))
    newstate = TCP_STATE(int(ev.newstate))

    if newstate in TCP_STATES_OPEN and oldstate not in TCP_STATES_OPEN:
        logger.debug(f"Connection opened: src={saddr} dport={dport} pid={ev.pid} comm={ev.task.decode()}")
        delta = 1
    elif oldstate in TCP_STATES_OPEN and newstate in TCP_STATES_CLOSE:
        logger.debug(f"Connection closed: src={saddr} dport={dport} pid={ev.pid} comm={ev.task.decode()}")
        delta = -1
    else:
        logger.debug(f"Ignored state change: {oldstate.name} -> {newstate.name} ({saddr} -> {dport})")
        return  # ignore other state transitions

    with lock:
        prev = active_count
        active_count += delta
        # clamp, because networks are messy and humans are worse
        if active_count < 0:
            active_count = 0
        now = active_count

    # transitions
    if prev == 0 and now > 0:
        transition_q.put("active")
        logger.info(f"ACTIVE  +{delta} conns={now} gpu_mode={'IDLE' if idle_flag.is_set() else 'ACTIVE'}")
    elif prev > 0 and now == 0:
        transition_q.put("idle")
        logger.info(
            f"IDLE    -{abs(delta)} conns={now} gpu_mode={'IDLE' if idle_flag.is_set() else 'ACTIVE'}"
        )
    else:
        timestamp = perf_counter()
        if timestamp - last_log > LOG_INTERVAL_SEC:
            last_log = timestamp
            logger.info(f"STATUS  conns={now} gpu_mode={'IDLE' if idle_flag.is_set() else 'ACTIVE'}")


def handle_ipv4_event(cpu, data, size):
    sock_inet_set_state_cb(cpu, data, size, family=AF_INET)


def handle_ipv6_event(cpu, data, size):
    sock_inet_set_state_cb(cpu, data, size, family=AF_INET6)


def main():
    logger.info(f"memscaler will monitor inbound TCP connections on port {MONITORED_PORT}")

    # load BPF program
    bpf_file = Path(__file__).with_suffix(".bpf.c")
    if not bpf_file.exists():
        raise FileNotFoundError(f"BPF source file not found: {bpf_file}")
    bpf_text = bpf_file.read_text()

    # apply dport filter
    dport_str = r"if (dport != MONITORED_PORT) { last.delete(&sk); return 0; }"
    bpf_text = bpf_text.replace("FILTER_DPORT", dport_str.replace("MONITORED_PORT", str(MONITORED_PORT)))

    if IPV4_ONLY is True:
        bpf_text = bpf_text.replace("FILTER_FAMILY", r"if (family != AF_INET) { return 0; }")

    # clean up unused filters
    bpf_text = bpf_text.replace("FILTER_PID", "")
    bpf_text = bpf_text.replace("FILTER_FAMILY", "")
    bpf_text = bpf_text.replace("FILTER_DPORT", "")

    # initialize BPF
    logger.info("Initializing eBPF program...")
    with BPF(text=bpf_text, cflags=BPF_CFLAGS) as b:
        # start GPU worker thread
        logger.info("Starting GPU worker thread...")
        transition_q.put("idle-now")  # start in idle mode
        worker_thread = threading.Thread(
            target=gpu_worker_func,
            name="gpu-worker",
            kwargs={"shutdown_evt": shutdown_evt, "transition_q": transition_q},
        )

        b["ipv4_events"].open_perf_buffer(handle_ipv4_event, page_cnt=64)
        b["ipv6_events"].open_perf_buffer(handle_ipv6_event, page_cnt=64)
        logger.info("BPF program loaded and attached, starting event loop...")
        worker_thread.start()

        try:
            while True:
                sys.stdout.flush()
                b.perf_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Shutting down...")
            shutdown_evt.set()

    logger.info("eBPF cleanup complete")
    if worker_thread.is_alive():
        worker_thread.join(timeout=5)
        logger.info("GPU worker thread exited")

    # Restore performance mode on exit
    set_gpu_performance_mode(force=True)

    raise SystemExit(0)


if __name__ == "__main__":
    main()

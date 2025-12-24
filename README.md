# memscaler

memscaler is a hacky little python+bpfcc+eBPF tool to help save power when running ML inference servers
on an nvidia datacenter-class GPU like the A40, which:

- only exposes 2 different memory clock speeds, 405MHz and 7251MHz
- consumes ~18W at the lower memory clock
- consumes ~80W at the higher memory clock
- refuses to clock down to the lower clock as long as there's an active compute context of any kind

I don't feel like blowing ~60W x2 all the time when the server is idle more often than not, but I don't
want to deal with proxying the API/websockets, so... eBPF it is![^1]

## so what does it do

memscaler:
-  monitors incoming tcp connections on a specific port (e.g. 5000 for llama.cpp's server) via an eBPF tracepoint
-  tracks how many active connections there are
-  when there are no active connections, starts a timer (default: 60 seconds)
-  when the timer expires, locks the nvidia GPU memory clock to the low state (405MHz) via `nvidia-smi -lmc 405`
-  when a new connection comes in, resets the memory clock to auto mode via `nvidia-smi -rmc`
-  repeats

## requirements

-  root privileges or `CAP_SYS_ADMIN` to load eBPF programs 
   -  there's probably a more restricted capability that would work but I haven't looked into it
-  `nvidia-smi` that has the `-lmc` and `-rmc` options (should be available on any driver from like 450+)
-  bpfcc python bindings (e.g. `python3-bpfcc`) on debian-based distros, and use of system python
   -  `uv venv --system-site-packages --no-managed-python .venv` then `uv sync` should do the trick
   -  in theory you could build bpfcc from source in a venv, but I couldn't see a straightforward way to do that because venvs don't have python dev headers
   -  if you're unhinged enough to use this yourself and *do* manage to make it work, 1. u ok fam? 2. please open a PR
-  kernel version 4.16 or later because the tracepoint didn't exist before that
   -  if `grep /sys/kernel/debug/tracing/available_events -e 'inet_sock_set_state'` returns nothing, you're out of luck
-  a disturbing level of trust in the quality of this code

## usage

if you can't work out how to use this yourself, you probably *shouldn't*, so I'm not going to tell you how

also I didn't even put in an actual CLI so you'll have to edit some constants to your liking in `src/memscaler/memscaler.py`

## acknowledgements and license

this is based heavily on the `tcpaccept` example from the `bcc` repo [here](https://github.com/iovisor/bcc/blob/master/tools/tcpaccept.py) and is thus
licensed under the Apache 2.0 license, same as that repo.


[^1]: i'm aware this is an insanely overengineered solution when i could probably just watch the inference server's stdout for activity but eBPF seemed more fun

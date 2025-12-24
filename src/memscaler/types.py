import ctypes as ct
from enum import Enum
from typing import Annotated, ClassVar, get_args, get_origin


# Build ctypes layouts from annotations; Annotated[T, ctype, bit_size?] drives _fields_.
def _field_from_annotation(name: str, annotation: object) -> tuple[str, type, int] | tuple[str, type] | None:
    origin = get_origin(annotation)
    if origin is ClassVar:
        return None

    if origin is Annotated:
        args = get_args(annotation)
        ctype: type | None = None
        bit_size: int | None = None
        for meta in args[1:]:
            if isinstance(meta, int) and ctype is not None:
                bit_size = meta
                break
            if ctype is None and isinstance(meta, type):
                ctype = meta
        if ctype is None and isinstance(args[0], type):
            ctype = args[0]
        if ctype is None:
            raise TypeError(f"{name} is missing ctypes metadata")
        if bit_size is None:
            return (name, ctype)
        return (name, ctype, bit_size)

    if isinstance(annotation, type):
        return (name, annotation)
    raise TypeError(f"{name} is not a ctypes type")


class CStructMeta(type(ct.Structure)):
    def __new__(mcls, name, bases, ns):
        if "_fields_" not in ns:
            annotations = ns.get("__annotations__", {})
            fields = []
            for field_name, annotation in annotations.items():
                if field_name.startswith("_"):
                    continue
                try:
                    field = _field_from_annotation(field_name, annotation)
                except TypeError:
                    continue
                if field is None:
                    continue
                fields.append(field)
            if fields:
                ns = dict(ns)
                ns["_fields_"] = fields
        return super().__new__(mcls, name, bases, ns)


# metaclass that auto-generates _fields_ from type annotations
class CStruct(ct.Structure, metaclass=CStructMeta):
    pass


# TCP connection state enum
class TCP_STATE(int, Enum):
    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11
    NEW_SYN_RECV = 12


TCP_STATES_CLOSE = {
    TCP_STATE.FIN_WAIT1,
    TCP_STATE.FIN_WAIT2,
    TCP_STATE.TIME_WAIT,
    TCP_STATE.CLOSE,
    TCP_STATE.CLOSE_WAIT,
    TCP_STATE.LAST_ACK,
    TCP_STATE.CLOSING,
}

TCP_STATES_OPEN = {
    TCP_STATE.ESTABLISHED,
    TCP_STATE.SYN_SENT,
    TCP_STATE.SYN_RECV,
    TCP_STATE.NEW_SYN_RECV,
}


# C struct definitions for BPF events used in memscaler.bpf.c
class IPv4Event(CStruct):
    ts_us: Annotated[int, ct.c_uint64]
    skaddr: Annotated[int, ct.c_uint64]
    saddr: Annotated[ct.Array[ct.c_uint32], ct.c_uint32 * 1]
    daddr: Annotated[ct.Array[ct.c_uint32], ct.c_uint32 * 1]
    span_us: Annotated[int, ct.c_uint64]
    pid: Annotated[int, ct.c_uint32]
    lport: Annotated[int, ct.c_uint16]
    dport: Annotated[int, ct.c_uint16]
    oldstate: Annotated[int, ct.c_int]
    newstate: Annotated[int, ct.c_int]
    task: Annotated[bytes, ct.c_char * 16]


class IPv6Event(CStruct):
    ts_us: Annotated[int, ct.c_uint64]
    skaddr: Annotated[int, ct.c_uint64]
    saddr: Annotated[ct.Array[ct.c_uint32], ct.c_uint32 * 4]
    daddr: Annotated[ct.Array[ct.c_uint32], ct.c_uint32 * 4]
    span_us: Annotated[int, ct.c_uint64]
    pid: Annotated[int, ct.c_uint32]
    lport: Annotated[int, ct.c_uint16]
    dport: Annotated[int, ct.c_uint16]
    oldstate: Annotated[int, ct.c_int]
    newstate: Annotated[int, ct.c_int]
    task: Annotated[bytes, ct.c_char * 16]

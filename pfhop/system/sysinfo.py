"""Host information read straight from /proc and statvfs (no extra deps)."""

from __future__ import annotations

import os
import platform
import socket
import threading
import time
from dataclasses import dataclass

# Filesystems worth showing on the dashboard.
_REAL_FS = {"xfs", "ext2", "ext3", "ext4", "btrfs", "vfat", "zfs", "f2fs", "nfs", "nfs4", "cifs"}


def os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    data[k] = v.strip('"')
    except OSError:
        pass
    return data


def uptime_seconds() -> int:
    try:
        with open("/proc/uptime") as fh:
            return int(float(fh.read().split()[0]))
    except OSError:
        return 0


def cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    return " ".join(line.split(":", 1)[1].split())
    except OSError:
        pass
    return platform.processor() or "unknown"


class _CpuSampler:
    """Computes CPU usage from /proc/stat deltas between calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._prev: tuple[float, int, int] | None = None  # (time, idle, total)

    @staticmethod
    def _read() -> tuple[int, int]:
        with open("/proc/stat") as fh:
            fields = [int(x) for x in fh.readline().split()[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
        return idle, sum(fields[:8])

    def percent(self) -> float:
        with self._lock:
            now = time.monotonic()
            if self._prev is None or now - self._prev[0] > 60:
                idle0, total0 = self._read()
                time.sleep(0.25)
                now = time.monotonic()
            else:
                _, idle0, total0 = self._prev
            idle1, total1 = self._read()
            self._prev = (now, idle1, total1)
            dt = total1 - total0
            if dt <= 0:
                return 0.0
            return round(100.0 * (1 - (idle1 - idle0) / dt), 1)


_cpu = _CpuSampler()


def meminfo() -> dict[str, int]:
    """Returns values in bytes."""
    info: dict[str, int] = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, rest = line.split(":", 1)
            info[key] = int(rest.split()[0]) * 1024
    return info


@dataclass
class Disk:
    mount: str
    device: str
    fstype: str
    total: int
    used: int
    free: int

    @property
    def percent(self) -> float:
        return round(100.0 * self.used / self.total, 1) if self.total else 0.0


def disks() -> list[Disk]:
    result: list[Disk] = []
    seen: set[str] = set()
    try:
        with open("/proc/mounts") as fh:
            mounts = [line.split()[:3] for line in fh]
    except OSError:
        return result
    for device, mount, fstype in mounts:
        if fstype not in _REAL_FS or mount in seen:
            continue
        if mount.startswith(("/sys", "/proc", "/run", "/dev")):
            continue
        seen.add(mount)
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        result.append(Disk(mount.replace("\\040", " "), device, fstype, total, used, free))
    result.sort(key=lambda d: d.mount)
    return result


def mount_for(path: str) -> str:
    """Return the mount point that contains `path`."""
    path = os.path.realpath(path)
    while not os.path.ismount(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


def primary_ip() -> str:
    """IP address of the interface holding the default route (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return ""


def collect() -> dict:
    rel = os_release()
    mem = meminfo()
    mem_total = mem.get("MemTotal", 0)
    mem_avail = mem.get("MemAvailable", mem.get("MemFree", 0))
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    load1, load5, load15 = os.getloadavg()
    cores = os.cpu_count() or 1
    return {
        "hostname": socket.gethostname(),
        "ip": primary_ip(),
        "os_name": rel.get("NAME", platform.system()),
        "os_version": rel.get("VERSION", ""),
        "os_pretty": rel.get("PRETTY_NAME", ""),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "uptime": uptime_seconds(),
        "cpu_model": cpu_model(),
        "cpu_cores": cores,
        "cpu_percent": _cpu.percent(),
        "load": (round(load1, 2), round(load5, 2), round(load15, 2)),
        "load_percent": round(100.0 * load1 / cores, 1),
        "mem_total": mem_total,
        "mem_used": mem_total - mem_avail,
        "mem_percent": round(100.0 * (mem_total - mem_avail) / mem_total, 1) if mem_total else 0,
        "swap_total": swap_total,
        "swap_used": swap_total - swap_free,
        "swap_percent": round(100.0 * (swap_total - swap_free) / swap_total, 1) if swap_total else 0,
        "disks": disks(),
        "time": int(time.time()),
    }

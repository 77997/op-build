#!/usr/bin/env python3
"""Stage-by-stage flashing of compute-2's side A from a verified side-A kit.

compute-2, an IBM Power S822LC 8335-GCA ("Firestone"), boots from a 64 MiB
PNOR.  Side A (0x0..0x2000000) holds the working firmware and side B
(0x2000000..0x4000000) the golden image, which is never written.  Every
skiboot, the golden one included, reads the partition table at 0x0, so a
damaged TOC@0x0 or BOOTKERNEL strands both sides, and the shared data
partitions (HBEL, GUARD, the VPD caches, NVRAM and the rest) and TEST hold
live machine state that must survive byte for byte.  This tool writes the kit
cut by ``check_pnor.py kit`` in three stages, proves every byte it writes by
reading it back, and restores any stage from a full backup of the flash.

Subcommands
-----------

``verify-kit KIT``
    Check SHA256SUMS, the manifest against the two TOC blocks and against
    the layout hard-coded here, every partition file's size, and that every
    range the kit would write is one of the two TOC blocks or lies inside
    side A's code region and overlaps no protected partition.

``plan KIT --stage STAGE [--device auto|IMAGE]``
    Print the ordered write list of a stage, mark the items the device
    already holds byte for byte (``flash`` skips them) and report any stage
    precondition that can be judged without the backup.

``flash KIT --stage STAGE --backup BACKUP --log LOG --yes [--device auto|IMAGE] [--pflash PATH]``
    Check every precondition, then erase, program and read back each item
    that differs, retrying an item once before aborting.

``rollback --stage STAGE --backup BACKUP --log LOG --yes [--device auto|IMAGE] [--pflash PATH]``
    Restore from BACKUP exactly the ranges the stage changes, with the same
    checks, verification and retry as ``flash``.

``--device auto`` (the default) resolves the whole-flash MTD afresh on every
run, because its index changes between boots, and proves it is the PNOR: a
64 MiB NOR MTD with 4 KiB erase blocks whose device-tree node is compatible
with ``ibm,opal-flash``.  Under skiboot 5.x it is named ``flash@0``.  The
new skiboot publishes fixed partitions under flash@0, so Debian's kernel
(without CONFIG_MTD_PARTITIONED_MASTER) registers only the partition MTDs:
the read-only BOOTKERNEL, CAPP, IMA_CATALOG and VERSION, which are ignored,
and the whole flash as a partition named ``PNOR``, which must then sit at
offset 0.  Exactly one MTD must qualify, and every log line names the one
used.  ``--device IMAGE``
works on a 64 MiB image file, so the whole procedure can be rehearsed with
the real pflash on a copy of the backup.

The backup and the log must be regular files, and the log may be neither
the backup nor the image: appending to an MTD node would write the log over
TOC@0x0.  Before any write, side B must match the backup.  A difference
from it in a partition the running system writes, or in a VPD cache that
hostboot rewrites at IPL, is only reported, because no stage writes or
restores any of them; a difference in TEST, BMC_INV or SECBOOT, which
nothing on this machine writes, refuses the run.  After the last item the
whole device is read again and every erase block outside the stage's items
must be as it was before the run, except in the partitions the running
system writes.

Stages
------

``hostboot``
    HBD, HBD_RW, HBI, SBEC, SBE, WINK, HBRT, PAYLOAD, OCC, CAPP,
    IMA_CATALOG and VERSION in ascending address order, then HBB.  Every one
    keeps its live offset; HBD and HBD_RW share the old HBD footprint.
``toc``
    toc0.bin at 0x0, then toc1.bin at 0x1FF8000.  Requires the hostboot
    stage to be fully on the device.  A run stopped between the two blocks
    can be resumed.  After this stage a real IPL may be taken before the
    bootkernel stage: the new hostboot and skiboot boot IBM's old
    BOOTKERNEL, and from Debian on the new firmware the flash appears as
    the ``PNOR`` MTD.  This tool accepts that MTD only with 4 KiB erase
    blocks, and skiboot 0c32c70b first tries IPMI HIOMAP with the BMC
    (platforms/astbmc/pnor.c lines 67-72), which may set another erase
    granule, so the MTD's erasesize must be checked after that IPL.
``bootkernel``
    BOOTKERNEL alone, once both TOC blocks are the kit's; that is its only
    requirement, so it may run before or after that IPL.

Rolling back ``hostboot`` restores the live code ranges (the old HBD
0x31000..0x91000 covers the new HBD and HBD_RW) and requires both TOC blocks
to be the backup's, so ``bootkernel`` and ``toc`` are rolled back first.

How pflash 7.0 is driven
------------------------

Each item is one ``pflash -F TARGET -f -e -a BASE -s SIZE -p FILE``
(skiboot v7.0 external/pflash/pflash.c):

* There is no ``-P``, so the FFS is never opened (``part_name`` gates it,
  lines 1092-1158) and ``erase_range`` and ``program_file`` return before
  ``ffs_update_act_size`` (lines 357-358 and 472-473): no TOC is read or
  rewritten.  pflash never refuses a write because of a READONLY flag; the
  flag on the TOC's own entry only suppresses that actual-size update (lines
  363-374 and 476-487), and skiboot's ``opal_flash_op`` (core/flash.c)
  exposes the raw flash without any region protection, so this tool's write
  fence is the only guard.
* ``-e`` with ``-a`` and ``-s`` erases exactly BASE..BASE+SIZE
  (``erase_range``, lines 293-355); ``-p`` then programs FILE at BASE and
  stops at SIZE bytes or at the end of FILE (``program_file``, lines
  412-470), so FILE always holds exactly SIZE bytes.
* ``-F`` names the flash file (lines 833-835).  It skips the MTD discovery
  and the write-protect call (lines 1049-1056 and 1196-1203), which on
  powerpc are a device-tree lookup and a no-op
  (external/common/arch_flash_powerpc.c lines 179-216).  The lookup
  (``get_dev_mtd``, lines 67-177) takes the first /sys/class/mtd entry in
  alphasort order whose device-tree node lies under the flash node: under
  skiboot 5.x that is flash@0, but on the new firmware every partition
  matches and a read-only one usually sorts first, so ``-F`` is required
  there.  ``-F`` opens the path through ``file_init_path`` (line 1058), which drives a character device as
  an MTD with MEMERASE and its 4 KiB erase block and a regular file as an
  image whose erase writes 0xFF (libflash/file.c lines 306-315 and 106-122).
  ``-F /dev/mtdN`` therefore writes exactly the whole-flash MTD this tool
  resolved and reads back through /dev/mtdNro, and ``-F IMAGE`` a rehearsal
  copy.  A regular file reports an erase granule of one byte (libflash/file.c
  line 255), so on an image pflash erases byte by byte: the same bytes, only
  more slowly.  Debian's opal-utils 7.0+dfsg-1 patches none of this code.
* ``-f`` clears ``must_confirm`` (line 831) so no "yes" prompt appears
  (stdin is /dev/null, so a prompt could only cancel); it also demotes the
  unaligned-erase error to a warning (lines 1159-1171), so this tool
  enforces 4 KiB alignment itself.
* Errors go to stderr and, from libflash, to stdout; the exit status is
  ``main``'s ``rc``, yet some refusals exit 0 (lines 1102-1103 and
  1159-1165), a short FILE programs silently and no backend verifies a write
  (``file_write``), so every item is read back and compared byte for byte.

SIGINT, SIGTERM, SIGHUP and SIGQUIT are held from the first read of the
device onwards (an ignored one stays ignored).  One that arrives before the
first write refuses the run with nothing written; later, an item being
written is always finished (pflash runs in its own session) and the run
stops cleanly before the next item, as it does for an opal-prd that starts
during the run and a log file that can no longer be written.  A failed
attempt is retried once after ``RETRY_DELAY_SECONDS``, so that a transient
OPAL_BUSY, such as the BMC holding the PNOR, can clear.

Exit status: 0 success, 1 refused before any write, 2 usage error, 3 aborted
after writing started, with the log stating exactly what the device holds.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from functools import partial
from pathlib import Path
from types import FrameType, TracebackType
from typing import Final, TextIO

import check_pnor as cp

IMAGE_SIZE: Final = cp.IMAGE_SIZE
ERASE_BLOCK: Final = cp.BLOCK_SIZE
CODE_WINDOW_END: Final = cp.BACKUP_TOC
FLASH_MTD_NAMES: Final = ("flash@0", "PNOR")
FLASH_MTD_TYPE: Final = "nor"
OPAL_FLASH_COMPATIBLE: Final = b"ibm,opal-flash"
MTD_WRITEABLE: Final = 0x400
DEFAULT_PFLASH: Final = Path("/usr/sbin/pflash")
WRITE_ATTEMPTS: Final = 2
RETRY_DELAY_SECONDS: Final = 10
READ_CHUNK: Final = 0x100000

EXIT_OK: Final = 0
EXIT_REFUSED: Final = 1
EXIT_USAGE: Final = 2
EXIT_ABORTED: Final = 3

LIVE_PROTECTED: Final[dict[str, tuple[int, int]]] = {
    "HBEL": (0x8000, 0x24000),
    "GUARD": (0x2C000, 0x5000),
    "DJVPD": (0x91000, 0x48000),
    "MVPD": (0xD9000, 0x90000),
    "CVPD": (0x169000, 0x48000),
    "ATTR_TMP": (0x1CA9000, 0x8000),
    "ATTR_PERM": (0x1CB1000, 0x8000),
    "TEST": (0x1DD9000, 0x9000),
    "NVRAM": (0x1DE2000, 0x90000),
    "FIRDATA": (0x1E72000, 0x3000),
    "BMC_INV": (0x1E75000, 0x9000),
    "SECBOOT": (0x1EA2000, 0x24000),
}
RUNTIME_WRITTEN: Final = frozenset({"GUARD", "HBEL", "NVRAM", "ATTR_TMP", "ATTR_PERM", "FIRDATA"})
FIRMWARE_MAINTAINED: Final = frozenset({"DJVPD", "MVPD", "CVPD"})
LIVE_CODE: Final[dict[str, tuple[int, int]]] = {
    "HBD": (0x31000, 0x60000),
    "HBI": (0x1B1000, 0x5A0000),
    "SBEC": (0x751000, 0x90000),
    "SBE": (0x7E1000, 0x48000),
    "WINK": (0x829000, 0x120000),
    "HBRT": (0x949000, 0x360000),
    "PAYLOAD": (0xCA9000, 0x100000),
    "BOOTKERNEL": (0xDA9000, 0xF00000),
    "OCC": (0x1CB9000, 0x120000),
    "CAPP": (0x1E7E000, 0x24000),
    "IMA_CATALOG": (0x1EC6000, 0x9000),
    "HBB": (0x1F60000, 0x90000),
    "VERSION": (0x1FF7000, 0x1000),
}
NEW_CODE: Final[dict[str, tuple[int, int]]] = {**LIVE_CODE, **cp.SPLIT_PARTITIONS}
PRIMARY_POINTERS: Final[dict[str, int]] = {
    "part": cp.PRIMARY_TOC,
    "BACKUP_PART": cp.BACKUP_TOC,
    "OTHER_SIDE": cp.OTHER_SIDE_TOC,
}
BACKUP_POINTERS: Final[dict[str, int]] = {
    "part": cp.BACKUP_TOC,
    "BACKUP_PART": cp.PRIMARY_TOC,
    "OTHER_SIDE": cp.OTHER_SIDE_BACKUP_TOC,
}
TOC_MISC_CHANGES: Final[dict[str, tuple[int, int]]] = {
    "part": (0x00, 0x40),
    "BACKUP_PART": (0x20, 0x60),
    "OTHER_SIDE": (0x20, 0x60),
}
KIT_TOC_FILES: Final = (("toc0.bin", cp.PRIMARY_TOC), ("toc1.bin", cp.BACKUP_TOC))
TOC_BLOCK_RANGES: Final = frozenset((base, cp.TOC_BLOCK_BYTES) for _name, base in KIT_TOC_FILES)
SUMS_LINE: Final = re.compile(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)")


class KitError(Exception):
    """The kit directory cannot be read as a side-A kit."""


class DeviceError(Exception):
    """The flash device or image cannot be used."""


class FenceError(Exception):
    """A write would touch flash that this tool must never write."""


class Refused(Exception):
    """One or more preconditions failed; nothing has been written."""

    def __init__(self, problems: Sequence[str]) -> None:
        """Keep every failed precondition for the log."""
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


class FlashAborted(Exception):
    """A write failed after its retry; the message states what the device holds."""


class Stage(Enum):
    """The three flashing stages, in the order they run."""

    HOSTBOOT = "hostboot"
    TOC = "toc"
    BOOTKERNEL = "bootkernel"


FLASH_NEXT: Final[dict[Stage, str]] = {
    Stage.HOSTBOOT: "next: flash --stage toc; do not reboot compute-2 before the toc stage is done",
    Stage.TOC: (
        "next: flash --stage bootkernel; a real IPL may be taken first, because the new hostboot and "
        "skiboot boot IBM's old BOOTKERNEL and the bootkernel stage only requires both TOC blocks to be "
        "the kit's; from Debian on the new firmware the flash appears as the 'PNOR' MTD, which this tool "
        "accepts only with 4 KiB erase blocks, and skiboot 0c32c70b first tries IPMI HIOMAP with the BMC, "
        "which may set another erase granule, so check the PNOR MTD's erasesize after that IPL"
    ),
    Stage.BOOTKERNEL: "side A now holds the whole kit",
}
ROLLBACK_NEXT: Final[dict[Stage, str]] = {
    Stage.BOOTKERNEL: "next: rollback --stage toc, then rollback --stage hostboot",
    Stage.TOC: "next: rollback --stage hostboot; do not reboot compute-2 before it is done",
    Stage.HOSTBOOT: "the hostboot ranges hold the backup's bytes again",
}


class TocState(Enum):
    """What the device's two side-A TOC blocks currently hold."""

    PRE = "pre-switch (both TOC blocks are the live layout's)"
    POST = "post-switch (both TOC blocks are the kit's)"
    INTERRUPTED = "toc stage interrupted (TOC@0x0 is the kit's, TOC@0x1ff8000 still the live layout's)"
    DIFFERS = "different from the backup's TOC blocks"
    UNKNOWN = "neither the backup's nor the kit's TOC blocks"


@dataclass(frozen=True)
class Region:
    """A named byte range of the flash."""

    name: str
    base: int
    size: int

    @property
    def end(self) -> int:
        """Return the first byte after the range."""
        return self.base + self.size

    def overlaps(self, base: int, size: int) -> bool:
        """Return whether ``base``..``base + size`` shares a byte with this range."""
        return base < self.end and self.base < base + size

    def label(self) -> str:
        """Format the range the way the log prints it."""
        return f"{self.name} {_span(self.base, self.size)}"


LIVE_PROTECTED_REGIONS: Final = tuple(
    Region(name, base, size) for name, (base, size) in LIVE_PROTECTED.items()
)


@dataclass(frozen=True)
class WriteItem:
    """One erase-and-program of an exact range with the bytes it must hold afterwards."""

    name: str
    base: int
    data: bytes

    @property
    def size(self) -> int:
        """Return the length of the range."""
        return len(self.data)

    @property
    def end(self) -> int:
        """Return the first byte after the range."""
        return self.base + len(self.data)


@dataclass(frozen=True)
class KitPart:
    """One side-A code partition of the kit, held in memory."""

    name: str
    base: int
    data: bytes


@dataclass(frozen=True)
class Kit:
    """A verified side-A kit, every file held in memory as verified."""

    version: str
    toc0: bytes
    toc1: bytes
    toc0_parsed: cp.Toc
    toc1_parsed: cp.Toc
    parts: dict[str, KitPart]
    do_not_write: tuple[Region, ...]


@dataclass(frozen=True)
class ManifestBlock:
    """A ``tocs`` record of the manifest."""

    file: str
    base: int
    size: int
    sha256: str


@dataclass(frozen=True)
class ManifestPart:
    """A ``partitions`` record of the manifest."""

    name: str
    file: str
    base: int
    size: int
    actual: int
    ecc: bool
    ffs_flags: int
    data_integ: int
    ver_check: int
    misc_flags: int
    sha256: str


@dataclass(frozen=True)
class ParsedManifest:
    """The kit's ``manifest.json`` with every field type-checked."""

    format: int
    version: str
    image_size: int
    tocs: tuple[ManifestBlock, ...]
    parts: tuple[ManifestPart, ...]
    do_not_write: tuple[Region, ...]


@dataclass(frozen=True)
class Backup:
    """A full 64 MiB backup of compute-2's flash taken before the first stage."""

    path: Path
    data: bytes
    sha256: str
    toc0: cp.Toc
    toc1: cp.Toc
    side_b: tuple[cp.Toc, ...]


@dataclass(frozen=True)
class Preservation:
    """How the side-B half and the protected partitions compare with the backup."""

    fatal: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class MtdInfo:
    """The sysfs facts about the whole-flash MTD; ``offset`` is ``None`` when it is not a partition."""

    index: int
    name: str
    offset: int | None
    size: int
    erasesize: int
    flags: int
    dev: tuple[int, int]
    ro_dev: tuple[int, int]


@dataclass(frozen=True)
class Device:
    """A flash target: the path pflash writes through and the path read back."""

    label: str
    target: Path
    readback: Path

    def read(self, base: int, size: int) -> bytes:
        """Read exactly ``size`` bytes at ``base`` from the read-back path.

        Every chunk of at most ``READ_CHUNK`` bytes is read with ``os.pread`` at
        its own explicit offset and never through the file position.  On the
        MTD a signal during the OPAL wait makes powernv_flash return -EINTR
        after mtdchar_read has already advanced the file position and copied
        the earlier kernel chunks, so a read that relied on the file position
        would be retried at the advanced offset into the old buffer position.
        CPython retries an interrupted ``pread`` at the same offset when the
        signal handler does not raise (PEP 475), so the assembled bytes always
        come from the offsets they belong to.
        """
        buffer = bytearray(size)
        done = 0
        try:
            with open(self.readback, "rb", buffering=0) as handle:
                while done < size:
                    chunk = os.pread(handle.fileno(), min(READ_CHUNK, size - done), base + done)
                    if not chunk:
                        raise DeviceError(
                            f"short read from {self.readback} at 0x{base + done:x} "
                            f"({done} of {size} bytes)"
                        )
                    buffer[done : done + len(chunk)] = chunk
                    done += len(chunk)
        except OSError as exc:
            raise DeviceError(f"cannot read {self.readback} at 0x{base:x}: {exc}") from exc
        return bytes(buffer)


@dataclass(frozen=True)
class SystemPaths:
    """Where the host's sysfs, device nodes, procfs and systemctl live."""

    sysfs_mtd: Path
    dev: Path
    proc: Path
    systemctl: str


SYSTEM: Final = SystemPaths(Path("/sys/class/mtd"), Path("/dev"), Path("/proc"), "systemctl")


def _span(base: int, size: int) -> str:
    """Format a range as ``0xBASE..0xEND``."""
    return f"0x{base:07x}..0x{base + size:07x}"


def _sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


class WriteFence:
    """Refuses every write that is not a TOC block or inside side A's code region.

    The protected set always holds compute-2's live shared and untouched
    partitions as hard-coded in this file, whatever a kit or backup claims;
    regions passed in can only widen it.
    """

    def __init__(self, extra: Sequence[Region] = ()) -> None:
        """Combine the hard-coded protected partitions with ``extra``."""
        unique = {
            (region.name, region.base, region.size): region for region in (*LIVE_PROTECTED_REGIONS, *extra)
        }
        self.protected = tuple(sorted(unique.values(), key=lambda region: (region.base, region.name)))

    def problems(self, name: str, base: int, size: int) -> list[str]:
        """Return every reason a write of ``size`` bytes at ``base`` is forbidden."""
        where = f"{name} {_span(base, size)}"
        issues: list[str] = []
        if size <= 0 or base < 0:
            issues.append(f"{where}: empty or negative range")
        if base % ERASE_BLOCK or size % ERASE_BLOCK:
            issues.append(f"{where}: not aligned to the 0x{ERASE_BLOCK:x}-byte erase block")
        if base + size > cp.SIDE_SIZE:
            issues.append(f"{where}: reaches 0x{cp.SIDE_SIZE:x} or beyond, and side B is never written")
        if (base, size) not in TOC_BLOCK_RANGES and (
            base < cp.CODE_REGION_START or base + size > CODE_WINDOW_END
        ):
            issues.append(
                f"{where}: neither one of the two TOC blocks nor inside side A's code region "
                f"0x{cp.CODE_REGION_START:x}..0x{CODE_WINDOW_END:x}"
            )
        for region in self.protected:
            if region.overlaps(base, size):
                issues.append(f"{where}: overlaps protected partition {region.label()}")
        return issues

    def check(self, name: str, base: int, size: int) -> None:
        """Raise ``FenceError`` unless the write is allowed."""
        issues = self.problems(name, base, size)
        if issues:
            raise FenceError("; ".join(issues))


def protected_regions(side_a: Sequence[cp.Toc], side_b: Sequence[cp.Toc]) -> list[Region]:
    """Collect every side-A byte range the given TOCs reserve for data.

    From side-A TOCs that is each shared or untouched partition; from side-B
    TOCs it is every partition they place below 0x2000000, which is what the
    golden side reads from side A.
    """
    regions: list[Region] = []
    for toc in side_a:
        regions.extend(
            Region(entry.name, entry.base, entry.size)
            for entry in toc.entries
            if entry.name in LIVE_PROTECTED
            or entry.name in cp.DATA_PARTITIONS
            or entry.name in cp.UNTOUCHED_LIVE_PARTITIONS
        )
    for toc in side_b:
        regions.extend(
            Region(entry.name, entry.base, entry.size)
            for entry in toc.entries
            if entry.name not in cp.TOC_ENTRY_NAMES and entry.base < cp.SIDE_SIZE
        )
    return regions


def describe_difference(expected: bytes, actual: bytes, base: int) -> str | None:
    """Summarise how ``actual`` differs from ``expected``; ``None`` when identical."""
    if expected == actual:
        return None
    if len(expected) != len(actual):
        return f"holds {len(actual)} bytes where {len(expected)} were expected"
    want = memoryview(expected)
    got = memoryview(actual)
    blocks = 0
    first = len(expected)
    for offset in range(0, len(expected), ERASE_BLOCK):
        if want[offset : offset + ERASE_BLOCK] == got[offset : offset + ERASE_BLOCK]:
            continue
        blocks += 1
        if first == len(expected):
            first = next(
                index
                for index in range(offset, min(offset + ERASE_BLOCK, len(expected)))
                if expected[index] != actual[index]
            )
    erased = ", every byte erased (0xff)" if actual.count(0xFF) == len(actual) else ""
    total = (len(expected) + ERASE_BLOCK - 1) // ERASE_BLOCK
    return (
        f"differs in {blocks} of {total} erase blocks, first at 0x{base + first:07x}{erased}, "
        f"sha256 {_sha256(actual)}"
    )


def _record(value: object, where: str) -> dict[str, object]:
    """Return ``value`` as a JSON object with string keys."""
    if not isinstance(value, dict):
        raise KitError(f"{where} is not a JSON object")
    record: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise KitError(f"{where} has a non-string key")
        record[key] = item
    return record


def _array(value: object, where: str) -> list[object]:
    """Return ``value`` as a JSON array."""
    if not isinstance(value, list):
        raise KitError(f"{where} is not a JSON array")
    items: list[object] = list(value)
    return items


def _int(record: dict[str, object], key: str, where: str) -> int:
    """Return the integer field ``key`` of ``record``."""
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise KitError(f"{where}.{key} is not an integer")
    return value


def _str(record: dict[str, object], key: str, where: str) -> str:
    """Return the string field ``key`` of ``record``."""
    value = record.get(key)
    if not isinstance(value, str):
        raise KitError(f"{where}.{key} is not a string")
    return value


def _bool(record: dict[str, object], key: str, where: str) -> bool:
    """Return the boolean field ``key`` of ``record``."""
    value = record.get(key)
    if not isinstance(value, bool):
        raise KitError(f"{where}.{key} is not a boolean")
    return value


def parse_manifest(raw: bytes) -> ParsedManifest:
    """Parse and type-check ``manifest.json`` as ``check_pnor.write_kit`` writes it."""
    try:
        document: object = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise KitError(f"manifest.json is not ASCII JSON: {exc}") from exc
    top = _record(document, "manifest")
    tocs: list[ManifestBlock] = []
    for index, value in enumerate(_array(top.get("tocs"), "manifest.tocs")):
        where = f"manifest.tocs[{index}]"
        record = _record(value, where)
        tocs.append(
            ManifestBlock(
                file=_str(record, "file", where),
                base=_int(record, "base", where),
                size=_int(record, "size", where),
                sha256=_str(record, "sha256", where),
            )
        )
    parts: list[ManifestPart] = []
    for index, value in enumerate(_array(top.get("partitions"), "manifest.partitions")):
        where = f"manifest.partitions[{index}]"
        record = _record(value, where)
        flags = _record(record.get("flags"), f"{where}.flags")
        parts.append(
            ManifestPart(
                name=_str(record, "name", where),
                file=_str(record, "file", where),
                base=_int(record, "base", where),
                size=_int(record, "size", where),
                actual=_int(record, "actual", where),
                ecc=_bool(record, "ecc", where),
                ffs_flags=_int(flags, "ffs_flags", f"{where}.flags"),
                data_integ=_int(flags, "data_integ", f"{where}.flags"),
                ver_check=_int(flags, "ver_check", f"{where}.flags"),
                misc_flags=_int(flags, "misc_flags", f"{where}.flags"),
                sha256=_str(record, "sha256", where),
            )
        )
    preserved: list[Region] = []
    for index, value in enumerate(_array(top.get("do_not_write"), "manifest.do_not_write")):
        where = f"manifest.do_not_write[{index}]"
        record = _record(value, where)
        preserved.append(
            Region(_str(record, "name", where), _int(record, "base", where), _int(record, "size", where))
        )
    image = _record(top.get("image"), "manifest.image")
    return ParsedManifest(
        format=_int(top, "format", "manifest"),
        version=_str(top, "version", "manifest"),
        image_size=_int(image, "size", "manifest.image"),
        tocs=tuple(tocs),
        parts=tuple(parts),
        do_not_write=tuple(preserved),
    )


def parse_sums(text: str) -> dict[str, str]:
    """Parse a ``sha256sum`` file into a file-to-digest mapping."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = SUMS_LINE.fullmatch(line)
        if match is None:
            raise KitError(f"SHA256SUMS line {number} is not '<sha256>  <plain file name>'")
        if match.group(2) in sums:
            raise KitError(f"SHA256SUMS lists {match.group(2)} twice")
        sums[match.group(2)] = match.group(1)
    return sums


def layout_problems(
    toc: cp.Toc, label: str, code: dict[str, tuple[int, int]], pointers: dict[str, int]
) -> list[str]:
    """List every way ``toc`` departs from a side-A layout with the given code partitions."""
    problems = [f"{label}: {problem}" for problem in toc.problems]
    if (
        toc.block_size != cp.BLOCK_SIZE
        or toc.block_count * toc.block_size != IMAGE_SIZE
        or toc.size_blocks * toc.block_size != cp.TOC_BLOCK_BYTES
    ):
        problems.append(
            f"{label}: {toc.size_blocks} TOC block(s) of 0x{toc.block_size:x} bytes over "
            f"{toc.block_count} blocks is not one 0x{cp.TOC_BLOCK_BYTES:x}-byte TOC on a 64 MiB flash"
        )
    expected = {*code, *LIVE_PROTECTED, *cp.TOC_ENTRY_NAMES}
    names = toc.names()
    problems.extend(f"{label}: no {name} entry" for name in sorted(expected - names))
    problems.extend(f"{label}: unexpected entry {name}" for name in sorted(names - expected))
    for name, (base, size) in [*code.items(), *LIVE_PROTECTED.items()]:
        entry = toc.find(name)
        if entry is not None and (entry.base, entry.size) != (base, size):
            problems.append(
                f"{label}: {name} is {_span(entry.base, entry.size)}, expected {_span(base, size)}"
            )
    for name, base in pointers.items():
        entry = toc.find(name)
        if entry is not None and entry.base != base:
            problems.append(f"{label}: {name} points at 0x{entry.base:x}, expected 0x{base:x}")
    return problems


def mirror_problems(primary: cp.Toc, backup: cp.Toc, label: str) -> list[str]:
    """List partitions the backup TOC places or flags differently from the primary."""
    problems: list[str] = []
    for entry in primary.entries:
        if entry.name in cp.TOC_ENTRY_NAMES:
            continue
        other = backup.find(entry.name)
        if other is None or other.identity() != entry.identity():
            problems.append(f"{label}: {entry.name} differs between the primary and the backup TOC")
    return problems


def transition_problems(live: cp.Toc, new: cp.Toc, label: str) -> list[str]:
    """List every difference between a live TOC and the kit's beyond the decided ones.

    The decided changes are HBD shrinking to 0x5A000, HBD_RW appearing at
    0x8B000/0x6000 with HBD's flags, 'part' misc 0x00 -> 0x40 and
    BACKUP_PART/OTHER_SIDE misc 0x20 -> 0x60; ids are allowed to be
    renumbered.  Anything else means the kit was not cut for this flash.
    """
    problems: list[str] = []
    header_live = (live.version, live.size_blocks, live.entry_size, live.block_size, live.block_count)
    header_new = (new.version, new.size_blocks, new.entry_size, new.block_size, new.block_count)
    if header_live != header_new:
        problems.append(f"{label}: TOC header geometry {header_live} became {header_new}")
    added = new.names() - live.names()
    removed = live.names() - new.names()
    if added != {"HBD_RW"} or removed:
        problems.append(
            f"{label}: partitions added {sorted(added)} and removed {sorted(removed)}; "
            "only HBD_RW may be added"
        )
    for entry in new.entries:
        source = live.find("HBD" if entry.name == "HBD_RW" else entry.name)
        if source is None:
            continue
        expected = source
        split = cp.SPLIT_PARTITIONS.get(entry.name)
        if split is not None:
            expected = replace(source, name=entry.name, base=split[0], size=split[1], actual=split[1])
        misc = TOC_MISC_CHANGES.get(entry.name)
        if misc is not None:
            if source.misc_flags != misc[0]:
                problems.append(
                    f"{label}: live {entry.name} misc is 0x{source.misc_flags:02x}, expected 0x{misc[0]:02x}"
                )
            expected = replace(expected, misc_flags=misc[1])
        if (expected.identity(), expected.actual) != (entry.identity(), entry.actual):
            problems.append(
                f"{label}: {entry.name} is {_span(entry.base, entry.size)} actual 0x{entry.actual:x} "
                f"integ 0x{entry.data_integ:04x} misc 0x{entry.misc_flags:02x}, the decided transition "
                f"gives {_span(expected.base, expected.size)} actual 0x{expected.actual:x} "
                f"integ 0x{expected.data_integ:04x} misc 0x{expected.misc_flags:02x}"
            )
    return problems


def verify_kit(root: Path) -> tuple[cp.Report, Kit | None]:
    """Verify a side-A kit; return the report and the kit when every check passed."""
    report = cp.Report()
    report.note(f"Kit: {root}")
    try:
        sums = parse_sums((root / "SHA256SUMS").read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, KitError) as exc:
        report.fail(f"SHA256SUMS: {exc}")
        return report, None
    blobs: dict[str, bytes] = {}
    for name, digest in sums.items():
        try:
            blob = (root / name).read_bytes()
        except OSError as exc:
            report.fail(f"{name}: {exc}")
            continue
        if _sha256(blob) != digest:
            report.fail(f"{name}: SHA-256 {_sha256(blob)} does not match SHA256SUMS {digest}")
            continue
        blobs[name] = blob
    try:
        unlisted = sorted(path.name for path in root.iterdir() if path.name not in {*sums, "SHA256SUMS"})
    except OSError as exc:
        report.fail(f"cannot list {root}: {exc}")
        return report, None
    for name in unlisted:
        report.note(f"  {name} is not listed in SHA256SUMS and is ignored")
    raw_manifest = blobs.get("manifest.json")
    if raw_manifest is None:
        report.fail("manifest.json is missing from SHA256SUMS or did not verify")
        return report, None
    try:
        manifest = parse_manifest(raw_manifest)
    except KitError as exc:
        report.fail(str(exc))
        return report, None

    if manifest.format != 1:
        report.fail(f"manifest format {manifest.format} is not 1")
    if manifest.image_size != IMAGE_SIZE:
        report.fail(f"manifest image size 0x{manifest.image_size:x} is not 0x{IMAGE_SIZE:x}")

    expected_blocks = sorted((name, base, cp.TOC_BLOCK_BYTES) for name, base in KIT_TOC_FILES)
    found_blocks = sorted((block.file, block.base, block.size) for block in manifest.tocs)
    if found_blocks != expected_blocks:
        report.fail(f"manifest tocs {found_blocks} are not exactly {expected_blocks}")
    toc_blobs: dict[str, bytes] = {}
    for block in manifest.tocs:
        blob = blobs.get(block.file)
        if blob is None:
            report.fail(f"{block.file} is missing from SHA256SUMS or did not verify")
            continue
        if _sha256(blob) != block.sha256:
            report.fail(f"{block.file}: SHA-256 does not match the manifest")
        if len(blob) != cp.TOC_BLOCK_BYTES:
            report.fail(f"{block.file} is {len(blob)} bytes, not 0x{cp.TOC_BLOCK_BYTES:x}")
            continue
        toc_blobs[block.file] = blob
    parsed: dict[str, cp.Toc] = {}
    for (name, _base), pointers in zip(KIT_TOC_FILES, (PRIMARY_POINTERS, BACKUP_POINTERS)):
        blob = toc_blobs.get(name)
        if blob is None:
            continue
        try:
            toc = cp.parse_toc(blob, 0)
        except cp.TocError as exc:
            report.fail(f"{name}: {exc}")
            continue
        for problem in layout_problems(toc, name, NEW_CODE, pointers):
            report.fail(problem)
        parsed[name] = toc
    toc0 = parsed.get("toc0.bin")
    toc1 = parsed.get("toc1.bin")
    if toc0 is not None and toc1 is not None:
        for problem in mirror_problems(toc0, toc1, "toc0.bin/toc1.bin"):
            report.fail(problem)

    names = [part.name for part in manifest.parts]
    if sorted(names) != sorted(cp.CODE_PARTITIONS):
        report.fail(f"manifest partitions {names} are not exactly {list(cp.CODE_PARTITIONS)}")
    parts: dict[str, KitPart] = {}
    for part in manifest.parts:
        where = f"partition {part.name}"
        decided = NEW_CODE.get(part.name)
        if decided is None:
            report.fail(f"{where} is not a side-A code partition")
            continue
        if (part.base, part.size) != decided:
            report.fail(f"{where} is {_span(part.base, part.size)}, the decided layout is {_span(*decided)}")
        if part.file != f"{part.name}.bin":
            report.fail(f"{where}: file {part.file} is not {part.name}.bin")
            continue
        blob = blobs.get(part.file)
        if blob is None:
            report.fail(f"{where}: {part.file} is missing from SHA256SUMS or did not verify")
            continue
        if _sha256(blob) != part.sha256:
            report.fail(f"{where}: {part.file} SHA-256 does not match the manifest")
        if len(blob) != part.size:
            report.fail(f"{where}: {part.file} is {len(blob)} bytes, the partition is {part.size}")
        for label, toc in (("toc0.bin", toc0), ("toc1.bin", toc1)):
            if toc is None:
                continue
            entry = toc.find(part.name)
            if entry is None:
                continue
            if (entry.base, entry.size) != (part.base, part.size):
                report.fail(
                    f"{where}: manifest {_span(part.base, part.size)} but {label} has "
                    f"{_span(entry.base, entry.size)}"
                )
            listed = (entry.ecc, entry.flags, entry.data_integ, entry.ver_check, entry.misc_flags)
            claimed = (part.ecc, part.ffs_flags, part.data_integ, part.ver_check, part.misc_flags)
            if entry.actual != part.actual:
                report.fail(f"{where}: manifest actual size 0x{part.actual:x} differs from {label}")
            if listed != claimed:
                report.fail(f"{where}: manifest flags differ from {label}")
        parts[part.name] = KitPart(part.name, part.base, blob)

    preserved_names = sorted(region.name for region in manifest.do_not_write)
    if preserved_names != sorted(LIVE_PROTECTED):
        report.fail(f"manifest do_not_write {preserved_names} is not exactly {sorted(LIVE_PROTECTED)}")
    for region in manifest.do_not_write:
        live = LIVE_PROTECTED.get(region.name)
        if live is not None and (region.base, region.size) != live:
            report.fail(f"do_not_write {region.label()} is not compute-2's live {_span(*live)}")

    version_part = parts.get("VERSION")
    if version_part is not None:
        try:
            text = cp.version_text(version_part.data)
        except cp.VersionError as exc:
            report.fail(f"VERSION.bin: {exc}")
        else:
            if text != manifest.version:
                report.fail("VERSION partition text differs from the manifest version")
    version_file = blobs.get("VERSION")
    if version_file is not None and version_file != manifest.version.encode("ascii", "replace"):
        report.fail("VERSION file differs from the manifest version")

    fence = WriteFence([*manifest.do_not_write, *protected_regions(list(parsed.values()), [])])
    writes = [Region(block.file, block.base, block.size) for block in manifest.tocs]
    writes.extend(Region(part.name, part.base, part.size) for part in manifest.parts)
    for region in writes:
        for issue in fence.problems(region.name, region.base, region.size):
            report.fail(issue)
    ordered = sorted(writes, key=lambda region: region.base)
    for first, second in zip(ordered, ordered[1:]):
        if second.base < first.end:
            report.fail(f"write ranges {first.label()} and {second.label()} overlap")

    if report.violations or toc0 is None or toc1 is None:
        return report, None
    report.note(f"  {len(writes)} write ranges verified for {manifest.version.splitlines()[0]}")
    return report, Kit(
        version=manifest.version,
        toc0=toc_blobs["toc0.bin"],
        toc1=toc_blobs["toc1.bin"],
        toc0_parsed=toc0,
        toc1_parsed=toc1,
        parts=parts,
        do_not_write=manifest.do_not_write,
    )


def _hbb_last(items: list[WriteItem]) -> list[WriteItem]:
    """Order items by address with HBB moved to the end."""
    return sorted(items, key=lambda item: (item.name == "HBB", item.base))


def kit_items(kit: Kit, stage: Stage) -> list[WriteItem]:
    """Return the ordered writes of ``stage`` from the kit."""
    if stage is Stage.TOC:
        return [
            WriteItem("toc0.bin", cp.PRIMARY_TOC, kit.toc0),
            WriteItem("toc1.bin", cp.BACKUP_TOC, kit.toc1),
        ]
    if stage is Stage.BOOTKERNEL:
        part = kit.parts["BOOTKERNEL"]
        return [WriteItem(part.name, part.base, part.data)]
    return _hbb_last(
        [
            WriteItem(part.name, part.base, part.data)
            for part in kit.parts.values()
            if part.name != "BOOTKERNEL"
        ]
    )


def rollback_items(backup: Backup, stage: Stage) -> list[WriteItem]:
    """Return the ordered restores of ``stage`` from the backup's live layout."""
    if stage is Stage.TOC:
        return [
            WriteItem(f"TOC@0x{base:x}", base, backup.data[base : base + cp.TOC_BLOCK_BYTES])
            for _name, base in KIT_TOC_FILES
        ]
    if stage is Stage.BOOTKERNEL:
        names = ["BOOTKERNEL"]
    else:
        names = [name for name in LIVE_CODE if name != "BOOTKERNEL"]
    return _hbb_last(
        [
            WriteItem(name, base, backup.data[base : base + size])
            for name, (base, size) in ((name, LIVE_CODE[name]) for name in names)
        ]
    )


def load_backup(path: Path, log: "ActionLog") -> Backup:
    """Read the backup, log its digest and prove it holds compute-2's live layout.

    The backup must be a regular file: an MTD node would make the flash its
    own backup, every comparison with it vacuous and every rollback a no-op.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise Refused([f"the backup {path} is not a regular file"])
        data = path.read_bytes()
    except OSError as exc:
        raise Refused([f"cannot read the backup {path}: {exc}"]) from exc
    digest = _sha256(data)
    log.event(f"backup {path}: {len(data)} bytes, sha256 {digest}")
    if len(data) != IMAGE_SIZE:
        raise Refused([f"the backup is {len(data)} bytes, not 0x{IMAGE_SIZE:x}"])
    problems: list[str] = []
    tocs: dict[int, cp.Toc] = {}
    for offset in (cp.PRIMARY_TOC, cp.BACKUP_TOC, cp.OTHER_SIDE_TOC, cp.OTHER_SIDE_BACKUP_TOC):
        try:
            tocs[offset] = cp.parse_toc(data, offset)
        except cp.TocError as exc:
            problems.append(f"backup: {exc}")
    primary = tocs.get(cp.PRIMARY_TOC)
    secondary = tocs.get(cp.BACKUP_TOC)
    if primary is not None:
        problems.extend(layout_problems(primary, "backup TOC@0x0", LIVE_CODE, PRIMARY_POINTERS))
    if secondary is not None:
        problems.extend(layout_problems(secondary, "backup TOC@0x1ff8000", LIVE_CODE, BACKUP_POINTERS))
    if primary is not None and secondary is not None:
        problems.extend(mirror_problems(primary, secondary, "backup"))
    side_b = tuple(tocs[offset] for offset in (cp.OTHER_SIDE_TOC, cp.OTHER_SIDE_BACKUP_TOC) if offset in tocs)
    for toc in side_b:
        problems.extend(f"backup side-B TOC@0x{toc.offset:x}: {problem}" for problem in toc.problems)
    if problems or primary is None or secondary is None:
        raise Refused(problems)
    return Backup(path=path, data=data, sha256=digest, toc0=primary, toc1=secondary, side_b=side_b)


def toc_state(image: bytes, backup: Backup, kit: Kit | None) -> TocState:
    """Classify the device's TOC blocks against the backup's and the kit's."""
    first = image[cp.PRIMARY_TOC : cp.PRIMARY_TOC + cp.TOC_BLOCK_BYTES]
    second = image[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES]
    old_first = backup.data[cp.PRIMARY_TOC : cp.PRIMARY_TOC + cp.TOC_BLOCK_BYTES]
    old_second = backup.data[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES]
    if (first, second) == (old_first, old_second):
        return TocState.PRE
    if kit is None:
        return TocState.DIFFERS
    if (first, second) == (kit.toc0, kit.toc1):
        return TocState.POST
    if first == kit.toc0 and second == old_second:
        return TocState.INTERRUPTED
    return TocState.UNKNOWN


def plan_toc_state(image: bytes, kit: Kit) -> tuple[TocState, list[str]]:
    """Classify the device's TOC blocks without a backup.

    Pre-switch here means both blocks parse and differ from the kit's
    exactly by the decided transition, i.e. they are the live layout the kit
    was cut against.
    """
    first = image[cp.PRIMARY_TOC : cp.PRIMARY_TOC + cp.TOC_BLOCK_BYTES]
    second = image[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES]
    if (first, second) == (kit.toc0, kit.toc1):
        return TocState.POST, []
    problems: list[str] = []
    try:
        live_second = cp.parse_toc(image, cp.BACKUP_TOC)
        problems.extend(transition_problems(live_second, kit.toc1_parsed, "device TOC@0x1ff8000 -> toc1.bin"))
    except cp.TocError as exc:
        problems.append(f"device TOC@0x1ff8000: {exc}")
    if first == kit.toc0:
        return (TocState.INTERRUPTED, []) if not problems else (TocState.UNKNOWN, problems)
    try:
        live_first = cp.parse_toc(image, cp.PRIMARY_TOC)
        problems.extend(transition_problems(live_first, kit.toc0_parsed, "device TOC@0x0 -> toc0.bin"))
    except cp.TocError as exc:
        problems.append(f"device TOC@0x0: {exc}")
    return (TocState.PRE, []) if not problems else (TocState.UNKNOWN, problems)


def flash_requirements(stage: Stage, state: TocState, image: bytes, kit: Kit) -> list[str]:
    """Return why ``stage`` may not run on a device in ``state`` holding ``image``."""
    if state in (TocState.UNKNOWN, TocState.DIFFERS):
        return [f"TOC@0x0 and TOC@0x1ff8000 are {state.value}"]
    problems: list[str] = []
    if stage is Stage.HOSTBOOT and state is TocState.INTERRUPTED:
        problems.append("the toc stage was interrupted; finish it with --stage toc or roll it back first")
    if stage is Stage.TOC:
        missing = [
            item.name for item in kit_items(kit, Stage.HOSTBOOT) if image[item.base : item.end] != item.data
        ]
        if missing:
            problems.append(
                f"stage toc needs the hostboot stage fully on the device; these differ: {', '.join(missing)}"
            )
    if stage is Stage.BOOTKERNEL and state is not TocState.POST:
        problems.append(f"stage bootkernel needs both TOC blocks to be the kit's; they are {state.value}")
    return problems


def rollback_requirements(stage: Stage, state: TocState) -> list[str]:
    """Return why the rollback of ``stage`` may not run on a device in ``state``."""
    if stage is Stage.HOSTBOOT and state is not TocState.PRE:
        return [
            f"rolling back hostboot needs both TOC blocks to be the backup's, they are {state.value}; "
            "roll back the bootkernel and toc stages first"
        ]
    return []


def compare_preserved(image: bytes, backup: bytes) -> Preservation:
    """Compare side B and every protected partition of ``image`` with the backup.

    Side B differing from the backup is fatal.  No protected partition is
    ever written or restored by any stage, so where a known writer exists a
    difference only means the backup's copy is stale and is reported as a
    note: the running system writes the ``RUNTIME_WRITTEN`` partitions, and
    hostboot rewrites the ``FIRMWARE_MAINTAINED`` VPD caches at IPL (the MVPD
    SB keyword on an SBE update, and a cache whose part or serial number no
    longer matches its SEEPROM).  TEST, BMC_INV and SECBOOT have no writer on
    this machine, so a difference there stays fatal.  A change during a run
    is judged by ``changes_outside`` instead, which stays fatal for every
    partition but the runtime-written ones.
    """
    fatal: list[str] = []
    notes: list[str] = []
    side_b = describe_difference(backup[cp.SIDE_SIZE :], image[cp.SIDE_SIZE :], cp.SIDE_SIZE)
    if side_b is not None:
        fatal.append(f"side B {_span(cp.SIDE_SIZE, cp.SIDE_SIZE)} differs from the backup: {side_b}")
    for region in LIVE_PROTECTED_REGIONS:
        difference = describe_difference(
            backup[region.base : region.end], image[region.base : region.end], region.base
        )
        if difference is None:
            continue
        if region.name in RUNTIME_WRITTEN:
            notes.append(
                f"{region.label()} differs from the backup (the running system writes it): {difference}"
            )
        elif region.name in FIRMWARE_MAINTAINED:
            notes.append(
                f"{region.label()} differs from the backup (hostboot rewrites this VPD cache at IPL; the "
                f"backup's copy is stale and no stage ever writes or restores it): {difference}"
            )
        else:
            fatal.append(f"{region.label()} differs from the backup: {difference}")
    return Preservation(tuple(fatal), tuple(notes))


def changes_outside(before: bytes, after: bytes, items: Sequence[WriteItem]) -> Preservation:
    """Compare every erase block the items do not cover with its content before the run.

    A change in a partition the running system writes is a note; any other
    change, a TOC field rewritten by pflash or a stray write anywhere on the
    flash among them, is fatal.
    """
    old = memoryview(before)
    new = memoryview(after)
    runtime = [region for region in LIVE_PROTECTED_REGIONS if region.name in RUNTIME_WRITTEN]
    stray: list[tuple[int, int]] = []
    noted: set[str] = set()
    for offset in range(0, IMAGE_SIZE, ERASE_BLOCK):
        if old[offset : offset + ERASE_BLOCK] == new[offset : offset + ERASE_BLOCK]:
            continue
        if any(item.base <= offset < item.end for item in items):
            continue
        owner = next((region for region in runtime if region.overlaps(offset, ERASE_BLOCK)), None)
        if owner is not None:
            noted.add(owner.name)
        elif stray and stray[-1][1] == offset:
            stray[-1] = (stray[-1][0], offset + ERASE_BLOCK)
        else:
            stray.append((offset, offset + ERASE_BLOCK))
    fatal = tuple(
        f"{_span(base, end - base)} changed during this run although it was not written: "
        f"{describe_difference(before[base:end], after[base:end], base)}"
        for base, end in stray
    )
    notes = tuple(
        f"{region.label()} changed during this run (the running system writes it)"
        for region in runtime
        if region.name in noted
    )
    return Preservation(fatal, notes)


def _sysfs_text(path: Path) -> str:
    """Read one sysfs attribute."""
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise DeviceError(f"cannot read {path}: {exc}") from exc


def _sysfs_int(path: Path) -> int:
    """Read one numeric sysfs attribute (decimal or 0x-prefixed)."""
    text = _sysfs_text(path)
    try:
        return int(text, 0)
    except ValueError as exc:
        raise DeviceError(f"{path} holds {text!r}, not a number") from exc


def _sysfs_dev(path: Path) -> tuple[int, int]:
    """Read a sysfs ``dev`` attribute as (major, minor)."""
    text = _sysfs_text(path)
    match = re.fullmatch(r"(\d+):(\d+)", text)
    if match is None:
        raise DeviceError(f"{path} holds {text!r}, not MAJOR:MINOR")
    return int(match.group(1)), int(match.group(2))


def _sysfs_bytes(path: Path) -> bytes:
    """Read one binary sysfs attribute, such as a device-tree property."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DeviceError(f"cannot read {path}: {exc}") from exc


def _sysfs_offset(node: Path) -> int | None:
    """Read an MTD's ``offset`` attribute; ``None`` when the MTD has none because it is not a partition."""
    if not (node / "offset").exists():
        return None
    return _sysfs_int(node / "offset")


def _whole_flash_problems(node: Path, label: str) -> list[str]:
    """Return why the MTD at ``node`` is not the whole PNOR; an empty list when it is."""
    size = _sysfs_int(node / "size")
    erasesize = _sysfs_int(node / "erasesize")
    offset = _sysfs_offset(node)
    problems: list[str] = []
    if size != IMAGE_SIZE:
        problems.append(f"{label} is 0x{size:x} bytes, not 0x{IMAGE_SIZE:x}")
    if erasesize != ERASE_BLOCK:
        problems.append(f"{label} erases 0x{erasesize:x}-byte blocks, not 0x{ERASE_BLOCK:x}")
    if offset is not None and offset != 0:
        problems.append(f"{label} is a partition at offset 0x{offset:x}, not at 0x0")
    mtd_type = _sysfs_text(node / "type")
    if mtd_type != FLASH_MTD_TYPE:
        problems.append(f"{label} is of type {mtd_type!r}, not {FLASH_MTD_TYPE!r}")
    compatible = _sysfs_bytes(node / "device" / "of_node" / "compatible")
    if OPAL_FLASH_COMPATIBLE not in compatible.split(b"\0"):
        shown = compatible.rstrip(b"\0").replace(b"\0", b", ").decode("ascii", "replace")
        problems.append(
            f"{label}'s device-tree node is compatible with [{shown}], "
            f"not {OPAL_FLASH_COMPATIBLE.decode('ascii')}"
        )
    return problems


def find_flash_mtd(sysfs: Path) -> MtdInfo:
    """Find the single MTD that is the whole PNOR and prove it is the OPAL flash with the PNOR's geometry.

    skiboot 5.x publishes /ibm,opal/flash@0 without partitions, so Linux
    registers the whole flash as an MTD named ``flash@0``.  Newer skiboot
    adds a ``fixed-partitions`` node under it with read-only BOOTKERNEL,
    CAPP, IMA_CATALOG and VERSION partitions and a whole-flash partition
    labelled ``PNOR``; a kernel without CONFIG_MTD_PARTITIONED_MASTER, such
    as Debian's, then registers only those partition MTDs, each with an
    ``offset`` attribute and the flash@0 platform device as its sysfs
    ``device``.  So the MTD must be named ``flash@0`` or ``PNOR``, be a
    64 MiB NOR device with 4 KiB erase blocks whose device-tree node (the
    platform device's) is compatible with ``ibm,opal-flash``, the node
    skiboot creates for the PNOR and the only one Linux's powernv_flash
    driver binds, and, when it is a partition, start at offset 0.  Smaller
    partitions of the same flash never qualify and are ignored; exactly one
    MTD must qualify.  The ``mtdNro`` twins are skipped.
    """
    try:
        entries = sorted(sysfs.iterdir())
    except OSError as exc:
        raise DeviceError(f"cannot list {sysfs}: {exc}") from exc
    qualified: list[tuple[int, str]] = []
    found: list[str] = []
    for entry in entries:
        match = re.fullmatch(r"mtd(\d+)", entry.name)
        if match is None:
            continue
        index = int(match.group(1))
        name = _sysfs_text(entry / "name")
        label = f"mtd{index} {name!r}"
        offset = _sysfs_offset(entry)
        where = "" if offset is None else f" at offset 0x{offset:x}"
        described = f"{label} of 0x{_sysfs_int(entry / 'size'):x} bytes{where}"
        if name not in FLASH_MTD_NAMES:
            found.append(described)
            continue
        try:
            problems = _whole_flash_problems(entry, label)
        except DeviceError as exc:
            problems = [str(exc)]
        if problems:
            found.append(f"{described} ({'; '.join(problems)})")
        else:
            found.append(described)
            qualified.append((index, name))
    if len(qualified) != 1:
        raise DeviceError(
            f"{len(qualified)} MTDs in {sysfs} are the whole PNOR (named {' or '.join(FLASH_MTD_NAMES)}, "
            f"0x{IMAGE_SIZE:x} bytes, 0x{ERASE_BLOCK:x}-byte erase blocks, type {FLASH_MTD_TYPE}, "
            f"node compatible with {OPAL_FLASH_COMPATIBLE.decode('ascii')}, offset 0x0 if a partition), "
            f"expected exactly one; found: {'; '.join(found) or 'no MTD'}"
        )
    index, name = qualified[0]
    node = sysfs / f"mtd{index}"
    return MtdInfo(
        index=index,
        name=name,
        offset=_sysfs_offset(node),
        size=_sysfs_int(node / "size"),
        erasesize=_sysfs_int(node / "erasesize"),
        flags=_sysfs_int(node / "flags"),
        dev=_sysfs_dev(node / "dev"),
        ro_dev=_sysfs_dev(sysfs / f"mtd{index}ro" / "dev"),
    )


def open_mtd(system: SystemPaths) -> tuple[Device, MtdInfo]:
    """Resolve the whole-flash MTD and prove its /dev nodes are that device."""
    info = find_flash_mtd(system.sysfs_mtd)
    node = system.dev / f"mtd{info.index}"
    readonly = system.dev / f"mtd{info.index}ro"
    for path, numbers in ((node, info.dev), (readonly, info.ro_dev)):
        try:
            status = os.stat(path)
        except OSError as exc:
            raise DeviceError(f"cannot stat {path}: {exc}") from exc
        if not stat.S_ISCHR(status.st_mode):
            raise DeviceError(f"{path} is not a character device")
        found = (os.major(status.st_rdev), os.minor(status.st_rdev))
        if found != numbers:
            raise DeviceError(f"{path} is device {found}, sysfs says {numbers}")
    return Device(f"{node} ({info.name}, read back through {readonly})", node, readonly), info


def open_image(path: Path, backup: Path | None) -> Device:
    """Use a 64 MiB regular file as the flash; it may never be the backup itself."""
    try:
        status = os.stat(path)
    except OSError as exc:
        raise DeviceError(f"cannot stat {path}: {exc}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise DeviceError(f"{path} is not a regular file; use --device auto for the flash")
    if status.st_size != IMAGE_SIZE:
        raise DeviceError(f"{path} is {status.st_size} bytes, not 0x{IMAGE_SIZE:x}")
    if backup is not None and backup.exists() and os.path.samefile(path, backup):
        raise DeviceError(f"{path} is the backup itself")
    resolved = path.resolve()
    return Device(f"image {resolved}", resolved, resolved)


def opal_prd_problems(system: SystemPaths) -> list[str]:
    """Return why opal-prd may be running; it must not touch the flash meanwhile."""
    problems: list[str] = []
    try:
        result = subprocess.run(
            [system.systemctl, "is-active", "opal-prd"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        problems.append(f"cannot run '{system.systemctl} is-active opal-prd': {exc}")
    else:
        state = result.stdout.strip()
        if state not in ("inactive", "failed"):
            problems.append(f"'systemctl is-active opal-prd' reports {state!r}; stop opal-prd first")
    for comm in sorted(system.proc.glob("[0-9]*/comm")):
        try:
            name = comm.read_text(encoding="ascii", errors="replace").strip()
        except OSError:
            continue
        if name == "opal-prd":
            problems.append(f"an opal-prd process is running (pid {comm.parent.name})")
    return problems


def pflash_command(pflash: Path, target: Path, base: int, size: int, blob: Path) -> list[str]:
    """Return the pflash invocation that erases and programs exactly one range."""
    return [
        str(pflash),
        "-F",
        str(target),
        "-f",
        "-e",
        "-a",
        f"0x{base:x}",
        "-s",
        f"0x{size:x}",
        "-p",
        str(blob),
    ]


def pflash_version(pflash: Path) -> str:
    """Return what ``pflash -v`` prints, or refuse when it cannot run."""
    try:
        result = subprocess.run(
            [str(pflash), "-v"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise Refused([f"cannot run {pflash}: {exc}"]) from exc
    if result.returncode != 0:
        raise Refused([f"'{pflash} -v' exited with status {result.returncode}"])
    return " ".join(result.stdout.split())


def _output_lines(raw: bytes) -> list[str]:
    """Split pflash output into lines, keeping the final state of each progress bar."""
    lines: list[str] = []
    for line in raw.decode("utf-8", "replace").split("\n"):
        last = line.split("\r")[-1].rstrip()
        if last:
            lines.append(last)
    return lines


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold an advisory exclusive lock on ``path`` so two runs never overlap."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise Refused([f"cannot open {path} to lock it: {exc}"]) from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Refused([f"{path} is locked by another run of this tool"]) from exc
        yield
    finally:
        os.close(descriptor)


def open_log(path: Path, forbidden: Sequence[Path]) -> TextIO:
    """Open ``path`` for appending, refusing anything but a regular file that is none of ``forbidden``.

    Appending to an MTD node writes at its offset 0, straight over TOC@0x0,
    and appending to the backup or the image corrupts it, so the log is
    checked before it is opened and again on the open descriptor.
    """
    existing: os.stat_result | None
    try:
        existing = os.stat(path)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise Refused([f"cannot stat the log {path}: {exc}"]) from exc
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise Refused([f"the log {path} is not a regular file"])
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC, 0o644
        )
    except OSError as exc:
        raise Refused([f"cannot open the log {path}: {exc}"]) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise Refused([f"the log {path} is not a regular file"])
        for other in forbidden:
            try:
                status = os.stat(other)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise Refused([f"cannot stat {other}: {exc}"]) from exc
            if (status.st_dev, status.st_ino) == (opened.st_dev, opened.st_ino):
                raise Refused([f"the log {path} is the same file as {other}"])
        return os.fdopen(descriptor, "a", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise


class ActionLog:
    """A timestamped record of every action, fsynced line by line and mirrored to a stream.

    A failure to write the file never interrupts a write in progress: it is
    reported on the stream and kept in ``file_error``, and the flasher stops
    before its next item.
    """

    def __init__(self, path: Path | None, out: TextIO, forbidden: Sequence[Path] = ()) -> None:
        """Open ``path`` for appending when given; it may be none of ``forbidden``."""
        self._out: TextIO | None = out
        self._file: TextIO | None = None
        self.file_error: str | None = None
        if path is not None:
            self._file = open_log(path, forbidden)

    def __enter__(self) -> "ActionLog":
        """Return the log for a ``with`` block."""
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the log file."""
        if self._file is not None:
            try:
                self._file.close()
            except OSError as exc:
                stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                self._mirror(f"{stamp} closing the log file failed: {exc}\n")
            self._file = None

    def _mirror(self, text: str) -> None:
        """Write ``text`` to the stream; once the stream fails, say so in the file and drop it."""
        if self._out is None:
            return
        try:
            self._out.write(text)
            self._out.flush()
        except OSError:
            self._out = None
            stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            self._record(f"{stamp} standard output is gone; logging to the file only\n")

    def _record(self, text: str) -> None:
        """Append ``text`` to the file and fsync it; on failure keep the error and close the file."""
        if self._file is None:
            return
        try:
            self._file.write(text)
            self._file.flush()
            os.fsync(self._file.fileno())
        except OSError as exc:
            self.file_error = f"writing the log file failed: {exc}"
            broken = self._file
            self._file = None
            try:
                broken.close()
            except OSError:
                pass
            stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            self._mirror(f"{stamp} {self.file_error}; the run stops before its next item\n")

    def event(self, message: str) -> None:
        """Record ``message`` with a UTC timestamp on every line."""
        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        text = "".join(f"{stamp} {line}\n" for line in (message.splitlines() or [""]))
        self._record(text)
        self._mirror(text)


class DeferredSignals:
    """Hold SIGINT, SIGTERM, SIGHUP and SIGQUIT so that a write in progress is always finished and verified.

    A signal whose disposition is ``SIG_IGN`` (SIGHUP under nohup, for
    example) keeps being ignored, and one whose handler was not installed
    from Python is left alone.
    """

    SIGNALS: Final = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)

    def __init__(self) -> None:
        """Start with no signal received."""
        self.received: int | None = None
        self._previous: dict[int, Callable[[int, FrameType | None], object] | int] = {}

    def __enter__(self) -> "DeferredSignals":
        """Install the deferring handlers on every held signal that is not ignored."""
        for signum in self.SIGNALS:
            previous = signal.getsignal(signum)
            if previous is not None and previous is not signal.SIG_IGN:
                self._previous[signum] = previous
                signal.signal(signum, self._handle)
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Restore the previous handlers."""
        for signum, handler in self._previous.items():
            signal.signal(signum, handler)
        self._previous.clear()

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        """Remember the signal; the run stops before its next item."""
        self.received = signum


@dataclass(frozen=True)
class Outcome:
    """What a completed run of items did."""

    written: tuple[str, ...]
    skipped: tuple[str, ...]


class Flasher:
    """Erases and programs exact ranges with pflash and proves every byte by reading it back."""

    def __init__(
        self,
        device: Device,
        pflash: Path,
        fence: WriteFence,
        log: ActionLog,
        scratch: Path,
        signals: DeferredSignals,
        backup: bytes,
        guard: Callable[[], list[str]],
        sleep: Callable[[float], None],
    ) -> None:
        """Bind the device, pflash, the fence, the log, the per-item host guard and the retry sleeper."""
        self.device = device
        self.pflash = pflash
        self.fence = fence
        self.log = log
        self.scratch = scratch
        self.signals = signals
        self.backup = backup
        self.guard = guard
        self.sleep = sleep

    def _stop_reason(self) -> str | None:
        """Return why the run must stop before its next item, if it must."""
        if self.signals.received is not None:
            return f"stopped by signal {signal.Signals(self.signals.received).name}"
        if self.log.file_error is not None:
            return f"stopped because {self.log.file_error}"
        problems = self.guard()
        if problems:
            return "stopped because a precondition no longer holds: " + "; ".join(problems)
        return None

    def apply(self, items: Sequence[WriteItem]) -> Outcome:
        """Write every item that differs, in order; raise ``FlashAborted`` on failure.

        The stop conditions are checked before an item is read and again
        after the read, immediately before it is written, so a signal that
        arrives during the read stops the run before that item.  While
        nothing has been written in this run a stop or a failed read raises
        ``Refused`` instead, because the device holds what it held before.
        """
        issues = [issue for item in items for issue in self.fence.problems(item.name, item.base, item.size)]
        if issues:
            raise Refused(issues)
        written: list[str] = []
        skipped: list[str] = []
        for index, item in enumerate(items):
            pending = [later.name for later in items[index:]]
            reason = self._stop_reason()
            if reason is not None:
                raise self._halt(f"{reason} before {item.name}", written, skipped, pending)
            try:
                current = self.device.read(item.base, item.size)
            except DeviceError as exc:
                raise self._halt(
                    f"cannot read {item.name} before writing it: {exc}", written, skipped, pending
                ) from exc
            if current == item.data:
                self.log.event(f"{item.name} {_span(item.base, item.size)}: already identical, skipped")
                skipped.append(item.name)
                continue
            reason = self._stop_reason()
            if reason is not None:
                raise self._halt(f"{reason} before {item.name}", written, skipped, pending)
            self._write(index, item, written, skipped, pending[1:])
            written.append(item.name)
        return Outcome(tuple(written), tuple(skipped))

    def _halt(
        self, headline: str, written: list[str], skipped: list[str], remaining: list[str]
    ) -> Refused | FlashAborted:
        """Return what stops the run before an item: ``Refused`` while this run has written nothing."""
        if written:
            return FlashAborted(self._state(headline, written, skipped, remaining))
        return Refused(
            [
                f"{headline}: interrupted before any write "
                f"(already identical, skipped: {', '.join(skipped) or 'none'})"
            ]
        )

    def _write(
        self, index: int, item: WriteItem, written: list[str], skipped: list[str], remaining: list[str]
    ) -> None:
        """Write one item, retrying once, and abort with the exact state if it never verifies.

        Before the retry the flasher waits ``RETRY_DELAY_SECONDS``: OPAL
        answers OPAL_BUSY while the BMC holds the PNOR or another flash
        operation runs, and an immediate retry would meet the same hold.
        """
        blob = self.scratch / f"{index:02d}-{re.sub(r'[^A-Za-z0-9_.-]', '_', item.name)}"
        try:
            blob.write_bytes(item.data)
        except OSError as exc:
            headline = f"cannot stage {item.name} for pflash in {self.scratch}: {exc}"
            raise FlashAborted(self._state(headline, written, skipped, [item.name, *remaining])) from exc
        failures: list[str] = []
        for attempt in range(1, WRITE_ATTEMPTS + 1):
            if attempt > 1:
                self.log.event(
                    f"{item.name}: waiting {RETRY_DELAY_SECONDS} s before attempt {attempt}, "
                    "so that a transient OPAL_BUSY (the BMC holding the PNOR) can clear"
                )
                self.sleep(RETRY_DELAY_SECONDS)
            try:
                self.fence.check(item.name, item.base, item.size)
            except FenceError as exc:
                headline = f"fence refused {item.name}: {exc}"
                raise FlashAborted(self._state(headline, written, skipped, [item.name, *remaining])) from exc
            failure = self._attempt(item, blob, attempt)
            if failure is None:
                self.log.event(
                    f"{item.name} {_span(item.base, item.size)}: written and read back identical "
                    f"(sha256 {_sha256(item.data)})"
                )
                return
            failures.append(f"attempt {attempt}: {failure}")
            self.log.event(f"{item.name}: attempt {attempt} failed: {failure}")
        summary = (
            f"{item.name} {_span(item.base, item.size)} failed {WRITE_ATTEMPTS} attempts:\n"
            + "\n".join(f"  {failure}" for failure in failures)
            + f"\n{item.name} {_span(item.base, item.size)} now holds {self._holdings(item)}"
        )
        raise FlashAborted(self._state(summary, written, skipped, remaining))

    def _holdings(self, item: WriteItem) -> str:
        """Describe what the range of a failed item holds now."""
        try:
            readback = self.device.read(item.base, item.size)
        except DeviceError as exc:
            return f"unknown bytes: the final read-back failed: {exc}"
        if readback == item.data:
            return "the intended bytes, although pflash reported failure"
        if readback == self.backup[item.base : item.end]:
            return "exactly the backup's bytes, as before this stage"
        if readback.count(0xFF) == len(readback):
            return "erased flash (every byte 0xff)"
        difference = describe_difference(item.data, readback, item.base)
        return f"neither the intended nor the backup's bytes: {difference}"

    def _attempt(self, item: WriteItem, blob: Path, attempt: int) -> str | None:
        """Run pflash once for ``item`` and read the range back; return a failure or ``None``."""
        command = pflash_command(self.pflash, self.device.target, item.base, item.size, blob)
        self.log.event(f"{item.name}: attempt {attempt}: {shlex.join(command)}")
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                start_new_session=True,
            )
        except OSError as exc:
            return f"pflash could not be started: {exc}"
        for line in _output_lines(result.stdout):
            self.log.event(f"  pflash stdout: {line}")
        for line in _output_lines(result.stderr):
            self.log.event(f"  pflash stderr: {line}")
        try:
            readback = self.device.read(item.base, item.size)
        except DeviceError as exc:
            return f"pflash exited with status {result.returncode}; read-back failed: {exc}"
        difference = describe_difference(item.data, readback, item.base)
        if result.returncode != 0:
            outcome = "the read-back matched" if difference is None else f"the read-back {difference}"
            return f"pflash exited with status {result.returncode}; {outcome}"
        if difference is not None:
            return f"pflash exited 0 but the read-back {difference}"
        return None

    @staticmethod
    def _state(headline: str, written: list[str], skipped: list[str], remaining: list[str]) -> str:
        """Describe exactly where the run stopped."""
        return (
            f"{headline}\n"
            f"written and verified in this run: {', '.join(written) or 'none'}\n"
            f"already identical, skipped: {', '.join(skipped) or 'none'}\n"
            f"not attempted: {', '.join(remaining) or 'none'}"
        )


def _execute(
    log: ActionLog,
    device: Device,
    pflash: Path,
    backup: Backup,
    kit: Kit | None,
    items: Sequence[WriteItem],
    requirements: Callable[[bytes, TocState], list[str]],
    fence: WriteFence,
    recovery: str,
    guard: Callable[[], list[str]],
    sleep: Callable[[float], None],
) -> int:
    """Check the device against the backup, then write ``items`` and prove the result.

    The signals are held from before the first read of the device, so one
    that arrives before the first write refuses the run cleanly instead of
    interrupting it with a traceback.
    """
    with exclusive_lock(device.target), DeferredSignals() as signals:
        image = device.read(0, IMAGE_SIZE)
        state = toc_state(image, backup, kit)
        log.event(f"TOC blocks: {state.value}")
        problems = requirements(image, state)
        preservation = compare_preserved(image, backup.data)
        for note in preservation.notes:
            log.event(f"note: {note}")
        problems.extend(preservation.fatal)
        problems.extend(issue for item in items for issue in fence.problems(item.name, item.base, item.size))
        if log.file_error is not None:
            problems.append(log.file_error)
        if problems:
            raise Refused(problems)
        log.event("side B matches the backup and no protected partition is written (differences as noted)")
        log.event(f"plan: {len(items)} items")
        for number, item in enumerate(items, 1):
            same = image[item.base : item.end] == item.data
            log.event(
                f"  {number:2d}. {item.name:<14} {_span(item.base, item.size)} 0x{item.size:07x} bytes "
                f"sha256 {_sha256(item.data)} {'identical, skip' if same else 'write'}"
            )
        if signals.received is not None:
            raise Refused(
                [f"signal {signal.Signals(signals.received).name} arrived: interrupted before any write"]
            )
        with tempfile.TemporaryDirectory(prefix="flash_side_a-") as scratch:
            flasher = Flasher(device, pflash, fence, log, Path(scratch), signals, backup.data, guard, sleep)
            try:
                outcome = flasher.apply(items)
            except FlashAborted as exc:
                log.event(f"ABORT: {exc}")
                log.event(f"Do not reboot compute-2 before this is resolved. {recovery}")
                return EXIT_ABORTED
            status = _post_check(log, device, backup, kit, image, items, outcome, recovery)
            if signals.received is not None:
                log.event(
                    f"signal {signal.Signals(signals.received).name} arrived during the last item "
                    "or the post-check, which were completed"
                )
            return status


def _post_check(
    log: ActionLog,
    device: Device,
    backup: Backup,
    kit: Kit | None,
    before: bytes,
    items: Sequence[WriteItem],
    outcome: Outcome,
    recovery: str,
) -> int:
    """Re-read the whole device and prove the stage changed nothing but its items."""
    try:
        after = device.read(0, IMAGE_SIZE)
    except DeviceError as exc:
        log.event(f"ABORT: post-check: {exc}")
        log.event(f"Do not reboot compute-2 before this is resolved. {recovery}")
        return EXIT_ABORTED
    outside = changes_outside(before, after, items)
    for note in outside.notes:
        log.event(f"note: {note}")
    final = list(compare_preserved(after, backup.data).fatal)
    final.extend(outside.fatal)
    final.extend(
        f"{item.name} {_span(item.base, item.size)} no longer holds the intended bytes"
        for item in items
        if after[item.base : item.end] != item.data
    )
    if final:
        for problem in final:
            log.event(f"ABORT: post-check: {problem}")
        log.event(f"Do not reboot compute-2 before this is resolved. {recovery}")
        return EXIT_ABORTED
    log.event(
        f"done: {len(outcome.written)} written ({', '.join(outcome.written) or 'none'}), "
        f"{len(outcome.skipped)} already identical ({', '.join(outcome.skipped) or 'none'}); "
        f"TOC blocks now {toc_state(after, backup, kit).value}"
    )
    return EXIT_OK


def _no_host_guard() -> list[str]:
    """Report nothing: an image file has no host state to re-check between items."""
    return []


def _prepare_device(
    spec: str, backup_path: Path, pflash: Path, log: ActionLog, system: SystemPaths
) -> tuple[Device, Callable[[], list[str]]]:
    """Resolve the target, check everything a write needs from the host and return the per-item guard.

    For the flash the guard repeats the opal-prd check before every item,
    so an opal-prd started during the run stops it before the next write.
    """
    problems: list[str] = []
    guard: Callable[[], list[str]] = _no_host_guard
    try:
        if spec == "auto":
            device, info = open_mtd(system)
            partition = "" if info.offset is None else f", partition at offset 0x{info.offset:x}"
            log.event(
                f"device {device.label}: 0x{info.size:x} bytes, erase block 0x{info.erasesize:x}, "
                f"flags 0x{info.flags:x}{partition}"
            )
            if not info.flags & MTD_WRITEABLE:
                problems.append(
                    f"mtd{info.index} {info.name!r} is not flagged writeable (flags 0x{info.flags:x})"
                )
            problems.extend(opal_prd_problems(system))
            guard = partial(opal_prd_problems, system)
        else:
            device = open_image(Path(spec), backup_path)
            log.event(f"device {device.label}")
    except DeviceError as exc:
        raise Refused([str(exc)]) from exc
    if not os.access(device.target, os.R_OK | os.W_OK):
        problems.append(f"{device.target} is not readable and writable by this user")
    if not os.access(device.readback, os.R_OK):
        problems.append(f"{device.readback} is not readable by this user")
    log.event(f"pflash {pflash}: {pflash_version(pflash)}")
    if problems:
        raise Refused(problems)
    return device, guard


def _log_forbidden(backup_path: Path, spec: str) -> list[Path]:
    """Return the files the log may never be: the backup and, for a rehearsal, the image."""
    return [backup_path] if spec == "auto" else [backup_path, Path(spec)]


def _self_command(*words: str) -> str:
    """Return a shell command line that runs this tool with ``words``.

    A run as root was started through sudo from an unprivileged shell, so
    the line then starts with ``sudo`` to be runnable there as printed.
    """
    prefix = ["sudo"] if os.geteuid() == 0 else []
    return shlex.join([*prefix, "python3", str(Path(__file__).resolve()), *words])


def run_flash(
    kit_root: Path,
    stage: Stage,
    backup_path: Path,
    spec: str,
    pflash: Path,
    log_path: Path,
    out: TextIO,
    system: SystemPaths = SYSTEM,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run one flashing stage; return the exit status."""
    try:
        log = ActionLog(log_path, out, _log_forbidden(backup_path, spec))
    except Refused as exc:
        out.write(f"REFUSED: {exc}\n")
        return EXIT_REFUSED
    with log:
        log.event(
            f"flash --stage {stage.value}: kit {kit_root}, backup {backup_path}, device {spec}, "
            f"pflash {pflash}, pid {os.getpid()}"
        )
        try:
            report, kit = verify_kit(kit_root)
            log.event(report.render().rstrip("\n"))
            if kit is None:
                raise Refused(["the kit failed verification"])
            backup = load_backup(backup_path, log)
            problems = transition_problems(backup.toc0, kit.toc0_parsed, "backup TOC@0x0 -> toc0.bin")
            problems.extend(
                transition_problems(backup.toc1, kit.toc1_parsed, "backup TOC@0x1ff8000 -> toc1.bin")
            )
            if problems:
                raise Refused(problems)
            device, guard = _prepare_device(spec, backup_path, pflash, log, system)
            side_a = [backup.toc0, backup.toc1, kit.toc0_parsed, kit.toc1_parsed]
            fence = WriteFence([*kit.do_not_write, *protected_regions(side_a, backup.side_b)])
            recovery = (
                "Re-run this stage to resume (identical items are skipped), or restore it with: "
                + _self_command(
                    "rollback", "--stage", stage.value, "--backup", str(backup_path),
                    "--device", spec, "--log", str(log_path), "--yes",
                )
            )
            if stage is Stage.TOC:
                recovery += " A damaged TOC@0x0 can only be repaired by that rollback."
            status = _execute(
                log,
                device,
                pflash,
                backup,
                kit,
                kit_items(kit, stage),
                lambda image, state: flash_requirements(stage, state, image, kit),
                fence,
                recovery,
                guard,
                sleep,
            )
            if status == EXIT_OK:
                log.event(FLASH_NEXT[stage])
            return status
        except (Refused, DeviceError) as exc:
            problems_seen = exc.problems if isinstance(exc, Refused) else (str(exc),)
            for problem in problems_seen:
                log.event(f"REFUSED: {problem}")
            log.event("nothing was written")
            return EXIT_REFUSED


def run_rollback(
    stage: Stage,
    backup_path: Path,
    spec: str,
    pflash: Path,
    log_path: Path,
    out: TextIO,
    system: SystemPaths = SYSTEM,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Restore one stage's ranges from the backup; return the exit status."""
    try:
        log = ActionLog(log_path, out, _log_forbidden(backup_path, spec))
    except Refused as exc:
        out.write(f"REFUSED: {exc}\n")
        return EXIT_REFUSED
    with log:
        log.event(
            f"rollback --stage {stage.value}: backup {backup_path}, device {spec}, pflash {pflash}, "
            f"pid {os.getpid()}"
        )
        try:
            backup = load_backup(backup_path, log)
            device, guard = _prepare_device(spec, backup_path, pflash, log, system)
            fence = WriteFence(protected_regions([backup.toc0, backup.toc1], backup.side_b))
            recovery = "Re-run the same rollback; items already restored are skipped."
            status = _execute(
                log,
                device,
                pflash,
                backup,
                None,
                rollback_items(backup, stage),
                lambda image, state: rollback_requirements(stage, state),
                fence,
                recovery,
                guard,
                sleep,
            )
            if status == EXIT_OK:
                log.event(ROLLBACK_NEXT[stage])
            return status
        except (Refused, DeviceError) as exc:
            problems_seen = exc.problems if isinstance(exc, Refused) else (str(exc),)
            for problem in problems_seen:
                log.event(f"REFUSED: {problem}")
            log.event("nothing was written")
            return EXIT_REFUSED


def run_plan(kit_root: Path, stage: Stage, spec: str, out: TextIO, system: SystemPaths = SYSTEM) -> int:
    """Print the ordered writes of ``stage`` and which of them the device already holds."""
    report, kit = verify_kit(kit_root)
    if kit is None:
        out.write(report.render())
        return EXIT_REFUSED
    try:
        device = open_mtd(system)[0] if spec == "auto" else open_image(Path(spec), None)
        image = device.read(0, IMAGE_SIZE)
    except DeviceError as exc:
        out.write(f"REFUSED: {exc}\n")
        return EXIT_REFUSED
    state, state_problems = plan_toc_state(image, kit)
    items = kit_items(kit, stage)
    fence = WriteFence([*kit.do_not_write, *protected_regions([kit.toc0_parsed, kit.toc1_parsed], [])])
    lines = [
        f"Kit {kit.version.splitlines()[0]}: stage {stage.value} on {device.label}",
        f"TOC blocks: {state.value}",
        *(f"  {problem}" for problem in state_problems),
    ]
    writes = 0
    for number, item in enumerate(items, 1):
        same = image[item.base : item.end] == item.data
        writes += 0 if same else 1
        lines.append(
            f"  {number:2d}. {item.name:<14} {_span(item.base, item.size)} 0x{item.size:07x} bytes "
            f"{'identical, skip' if same else 'write'}"
        )
        lines.extend(f"      FENCE: {issue}" for issue in fence.problems(item.name, item.base, item.size))
    lines.extend(f"flash would refuse: {problem}" for problem in flash_requirements(stage, state, image, kit))
    lines.append(f"{writes} to write, {len(items) - writes} already identical")
    out.write("\n".join(lines) + "\n")
    return EXIT_OK


def _arg_path(namespace: argparse.Namespace, name: str) -> Path:
    """Fetch a ``Path`` argument with a precise type."""
    value: object = getattr(namespace, name)
    if not isinstance(value, Path):
        raise TypeError(f"argument {name} is not a path")
    return value


def _arg_str(namespace: argparse.Namespace, name: str) -> str:
    """Fetch a ``str`` argument with a precise type."""
    value: object = getattr(namespace, name)
    if not isinstance(value, str):
        raise TypeError(f"argument {name} is not a string")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="flash_side_a.py",
        description="Flash compute-2's side A from a verified kit, stage by stage, or roll a stage back.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    stages = [stage.value for stage in Stage]
    verify = commands.add_parser("verify-kit", help="verify a side-A kit")
    verify.add_argument("kit", type=Path)
    plan = commands.add_parser("plan", help="print a stage's writes and what the device already holds")
    plan.add_argument("kit", type=Path)
    plan.add_argument("--stage", required=True, choices=stages)
    plan.add_argument(
        "--device", default="auto", help="'auto' for the whole-flash MTD (flash@0 or PNOR), or a 64 MiB image"
    )
    flash = commands.add_parser("flash", help="write one stage of the kit")
    flash.add_argument("kit", type=Path)
    rollback = commands.add_parser("rollback", help="restore one stage's ranges from the backup")
    for sub in (flash, rollback):
        sub.add_argument("--stage", required=True, choices=stages)
        sub.add_argument("--backup", type=Path, required=True, help="64 MiB backup taken before any stage")
        sub.add_argument(
            "--device",
            default="auto",
            help="'auto' for the whole-flash MTD (flash@0 or PNOR), or a 64 MiB image",
        )
        sub.add_argument("--log", type=Path, required=True, help="file every action is appended to")
        sub.add_argument("--pflash", type=Path, default=DEFAULT_PFLASH)
        sub.add_argument("--yes", action="store_true", required=True, help="confirm writing the flash")
    return parser


def main(
    argv: Sequence[str] | None = None,
    out: TextIO | None = None,
    system: SystemPaths = SYSTEM,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Command-line entry point; returns the process exit status."""
    stream = sys.stdout if out is None else out
    args = build_parser().parse_args(argv)
    command = _arg_str(args, "command")
    if command == "verify-kit":
        report, kit = verify_kit(_arg_path(args, "kit"))
        stream.write(report.render())
        return EXIT_OK if kit is not None else EXIT_REFUSED
    stage = Stage(_arg_str(args, "stage"))
    spec = _arg_str(args, "device")
    if command == "plan":
        return run_plan(_arg_path(args, "kit"), stage, spec, stream, system)
    backup = _arg_path(args, "backup").resolve()
    log_path = _arg_path(args, "log").resolve()
    pflash = _arg_path(args, "pflash")
    if command == "flash":
        kit = _arg_path(args, "kit").resolve()
        return run_flash(kit, stage, backup, spec, pflash, log_path, stream, system, sleep)
    return run_rollback(stage, backup, spec, pflash, log_path, stream, system, sleep)


if __name__ == "__main__":
    sys.exit(main())

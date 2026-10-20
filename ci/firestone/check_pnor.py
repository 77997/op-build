#!/usr/bin/env python3
"""Offline PNOR safety checker and side-A kit extractor for Firestone.

compute-2, an IBM Power S822LC 8335-GCA ("Firestone"), boots from a 64 MiB
PNOR.  The lower half (side A) holds the working firmware, the upper half
(side B) the golden image, and a set of shared data partitions (VPD caches,
GUARD records, NVRAM, error logs and so on) lives in the lower half and is
referenced by both sides.  A new build may only ever replace the two side-A
TOC blocks and the side-A code partitions; every data partition must keep its
live position, size and flags so that its content survives untouched.

This tool proves those invariants on a built ``firestone.pnor`` using nothing
but the Python standard library and the raw TOC blocks read from compute-2
(the fixtures), then cuts the side-A kit consumed by the flashing procedure.

Subcommands
-----------

``check IMAGE --fixtures DIR [--payload FILE] [--bootkernel FILE]``
    Parse the FFS TOCs at 0x0, BACKUP_PART and OTHER_SIDE, verify their
    checksums and geometry, compare the new side-A TOC with the live one,
    check the ECC of every ECC partition's written content, validate the
    xz PAYLOAD and the BOOTKERNEL ELF the way hostboot and skiboot consume
    them, validate the VERSION text, print a human-readable diff against
    the live TOC and exit with status 1 on any violation.  ``--payload``
    and ``--bootkernel`` additionally prove that those partitions start
    with exactly the given build outputs.

``kit IMAGE --fixtures DIR --out DIR``
    Run every ``check`` assertion and, only if all pass, write ``toc0.bin``
    (4 KiB at 0x0), ``toc1.bin`` (4 KiB at 0x1FF8000), every side-A code
    partition as an exact raw slice of its full partition size (ECC bytes
    included), ``VERSION`` (the VERSION partition's text),
    ``manifest.json`` and ``SHA256SUMS``.  Shared and data partitions are
    never emitted.  The fixtures are mandatory because a kit must never be
    cut from an image that has not passed every check.

``fwfeatures BLD_DEVTREE_C``
    Parse hostboot's static ``initFlagArray`` and assert that
    fw-count-cache-disabled is enabled while fw-bcctrl-serialized and
    fw-l1d-thread-split are disabled.
"""

import argparse
import hashlib
import json
import lzma
import re
import struct
import sys
import zlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Sequence, TypedDict

IMAGE_SIZE: Final = 0x4000000
BLOCK_SIZE: Final = 0x1000
SIDE_SIZE: Final = 0x2000000
TOC_BLOCK_BYTES: Final = 0x1000
PRIMARY_TOC: Final = 0x0
BACKUP_TOC: Final = 0x1FF8000
OTHER_SIDE_TOC: Final = 0x2000000
OTHER_SIDE_BACKUP_TOC: Final = 0x3FF8000
CODE_REGION_START: Final = 0x8000
CODE_REGION_END: Final = SIDE_SIZE

FFS_MAGIC: Final = 0x50415254
FFS_VERSION: Final = 1
FFS_HEADER_BYTES: Final = 48
FFS_ENTRY_BYTES: Final = 128
FFS_INTEG_ECC: Final = 0x8000
FFS_HEADER_FORMAT: Final = ">12I"
FFS_ENTRY_FORMAT: Final = ">16s7I4IBBHBB2s14II"

MISC_FLAG_NAMES: Final = (
    (0x80, "preserved"),
    (0x40, "readonly"),
    (0x20, "backup"),
    (0x10, "reprovision"),
    (0x08, "volatile"),
    (0x04, "clearecc"),
    (0x01, "golden"),
)

TOC_ENTRY_NAMES: Final = ("part", "BACKUP_PART", "OTHER_SIDE")
DATA_PARTITIONS: Final = (
    "HBEL",
    "GUARD",
    "DJVPD",
    "MVPD",
    "CVPD",
    "ATTR_TMP",
    "ATTR_PERM",
    "NVRAM",
    "FIRDATA",
    "BMC_INV",
    "SECBOOT",
)
CODE_PARTITIONS: Final = (
    "HBD",
    "HBD_RW",
    "HBI",
    "SBEC",
    "SBE",
    "WINK",
    "HBRT",
    "PAYLOAD",
    "BOOTKERNEL",
    "OCC",
    "CAPP",
    "IMA_CATALOG",
    "HBB",
    "VERSION",
)
UNTOUCHED_LIVE_PARTITIONS: Final = ("TEST",)
SPLIT_PARTITIONS: Final = {
    "HBD": (0x31000, 0x5A000),
    "HBD_RW": (0x8B000, 0x6000),
}
FIXED_PARTITIONS: Final = {
    "HBD": (0x31000, 0x5A000),
    "HBD_RW": (0x8B000, 0x6000),
    "PAYLOAD": (0xCA9000, 0x100000),
    "BOOTKERNEL": (0xDA9000, 0xF00000),
}
HBB_BASE: Final = 0x1F60000

FIXTURE_LIVE_A: Final = "compute-2-toc-0x0.bin"
FIXTURE_LIVE_A_BACKUP: Final = "compute-2-toc-0x1FF8000.bin"
FIXTURE_LIVE_B: Final = "compute-2-toc-0x2000000.bin"
FIXTURE_LIVE_B_BACKUP: Final = "compute-2-toc-0x3FF8000.bin"
FIXTURE_NAMES: Final = (
    FIXTURE_LIVE_A,
    FIXTURE_LIVE_A_BACKUP,
    FIXTURE_LIVE_B,
    FIXTURE_LIVE_B_BACKUP,
)
FIXTURE_SUMS: Final = "SHA256SUMS"

XZ_HEADER_MAGIC: Final = b"\xfd7zXZ\x00"
XZ_FOOTER_MAGIC: Final = b"YZ"
XZ_CHECK_CRC32: Final = 0x01
XZ_CHECK_NAMES: Final = {0x00: "none", 0x01: "CRC32", 0x04: "CRC64", 0x0A: "SHA-256"}
XZ_FILTER_LZMA2: Final = 0x21
HOSTBOOT_XZ_RATIO: Final = 16

ELF_MAGIC: Final = b"\x7fELF"
STB_CONTAINER_MAGIC: Final = b"\x17\x08\x20\x11"
LIVE_BOOTKERNEL_ELF_SIZE: Final = 14964984

VERSION_FORBIDDEN: Final = (
    (re.compile(r"\bunknown\b"), "'unknown' (git describe failed during the build)"),
    (re.compile(r"-dirty\b"), "'-dirty' (the build tree had uncommitted changes)"),
)

INIT_FLAG_ENABLED: Final = 0x8000000000000000
FW_FEATURE_EXPECTATIONS: Final = (
    ("fw-count-cache-disabled", True),
    ("fw-bcctrl-serialized", False),
    ("fw-l1d-thread-split", False),
)

ECC_MATRIX: Final = (
    0x0000E8423C0F99FF,
    0x00E8423C0F99FF00,
    0xE8423C0F99FF0000,
    0x423C0F99FF0000E8,
    0x3C0F99FF0000E842,
    0x0F99FF0000E8423C,
    0x99FF0000E8423C0F,
    0xFF0000E8423C0F99,
)
SYNDROME_GOOD: Final = 0xFF
SYNDROME_UE: Final = 0xFE
_GD: Final = SYNDROME_GOOD
_UE: Final = SYNDROME_UE
_E0: Final = 71
_E1: Final = 70
_E2: Final = 69
_E3: Final = 68
_E4: Final = 67
_E5: Final = 66
_E6: Final = 65
_E7: Final = 64
SYNDROME_MATRIX: Final = (
    _GD, _E7, _E6, _UE, _E5, _UE, _UE, 47, _E4, _UE, _UE, 37, _UE, 35, 39, _UE,
    _E3, _UE, _UE, 48, _UE, 30, 29, _UE, _UE, 57, 27, _UE, 31, _UE, _UE, _UE,
    _E2, _UE, _UE, 17, _UE, 18, 40, _UE, _UE, 58, 22, _UE, 21, _UE, _UE, _UE,
    _UE, 16, 49, _UE, 19, _UE, _UE, _UE, 23, _UE, _UE, _UE, _UE, 20, _UE, _UE,
    _E1, _UE, _UE, 51, _UE, 46, 9, _UE, _UE, 34, 10, _UE, 32, _UE, _UE, 36,
    _UE, 62, 50, _UE, 14, _UE, _UE, _UE, 13, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    _UE, 61, 8, _UE, 41, _UE, _UE, _UE, 11, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    15, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, 12, _UE, _UE, _UE, _UE, _UE,
    _E0, _UE, _UE, 55, _UE, 45, 43, _UE, _UE, 56, 38, _UE, 1, _UE, _UE, _UE,
    _UE, 25, 26, _UE, 2, _UE, _UE, _UE, 24, _UE, _UE, _UE, _UE, _UE, 28, _UE,
    _UE, 59, 54, _UE, 42, _UE, _UE, 44, 6, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    5, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    _UE, 63, 53, _UE, 0, _UE, _UE, _UE, 33, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    3, _UE, _UE, 52, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
    7, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, 60, _UE, _UE, _UE, _UE, _UE, _UE,
    _UE, _UE, _UE, _UE, 4, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE, _UE,
)


class TocError(Exception):
    """A TOC block is structurally unusable (bad magic, geometry, size)."""


class XzError(Exception):
    """The PAYLOAD is not an xz stream that hostboot master-p8 can decode."""


class ElfError(Exception):
    """The BOOTKERNEL is not an ELF image whose size skiboot can compute."""


class FixtureError(Exception):
    """The committed live TOC fixtures are missing, corrupt or tampered with."""


class VersionError(Exception):
    """The VERSION partition does not hold a usable op-build version text."""


class TocBlockRecord(TypedDict):
    """Manifest record of one TOC block shipped in the kit."""

    file: str
    base: int
    size: int
    sha256: str


class PartitionFlags(TypedDict):
    """Manifest record of a partition's FFS flags and user data."""

    ffs_flags: int
    chip: int
    compress_type: int
    data_integ: int
    ver_check: int
    misc_flags: int
    misc: list[str]


class PartitionRecord(TypedDict):
    """Manifest record of one side-A code partition shipped in the kit."""

    name: str
    file: str
    base: int
    size: int
    actual: int
    written: int
    ecc: bool
    flags: PartitionFlags
    sha256: str


class PreservedRecord(TypedDict):
    """Manifest record of a data partition that must never be written."""

    name: str
    base: int
    size: int
    ecc: bool


class ImageRecord(TypedDict):
    """Manifest record of the full image the kit was cut from."""

    size: int
    sha256: str


class Manifest(TypedDict):
    """The kit's ``manifest.json``."""

    format: int
    description: str
    version: str
    image: ImageRecord
    tocs: list[TocBlockRecord]
    partitions: list[PartitionRecord]
    do_not_write: list[PreservedRecord]


@dataclass(frozen=True)
class TocEntry:
    """One FFS v1 partition entry, with base and size converted to bytes."""

    name: str
    base: int
    size: int
    pid: int
    entry_id: int
    entry_type: int
    flags: int
    actual: int
    chip: int
    compress_type: int
    data_integ: int
    ver_check: int
    misc_flags: int

    @property
    def end(self) -> int:
        """Return the first byte after the partition."""
        return self.base + self.size

    @property
    def ecc(self) -> bool:
        """Return whether the partition carries skiboot-style ECC."""
        return bool(self.data_integ & FFS_INTEG_ECC)

    def misc_names(self) -> list[str]:
        """Return the names of the miscFlags bits that are set."""
        return [name for bit, name in MISC_FLAG_NAMES if self.misc_flags & bit]

    def identity(self) -> tuple[int, int, int, int, int, int, int, int, int]:
        """Return every field that pins a partition's place and treatment."""
        return (
            self.base,
            self.size,
            self.entry_type,
            self.flags,
            self.chip,
            self.compress_type,
            self.data_integ,
            self.ver_check,
            self.misc_flags,
        )


@dataclass(frozen=True)
class Toc:
    """A parsed FFS v1 TOC together with the non-fatal problems found in it."""

    offset: int
    version: int
    size_blocks: int
    entry_size: int
    block_size: int
    block_count: int
    entries: tuple[TocEntry, ...]
    problems: tuple[str, ...]

    def find(self, name: str) -> TocEntry | None:
        """Return the entry called ``name`` or ``None`` if it is absent."""
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def names(self) -> set[str]:
        """Return the set of partition names in this TOC."""
        return {entry.name for entry in self.entries}


@dataclass(frozen=True)
class EccScan:
    """Outcome of an ECC syndrome scan over a 9-bytes-per-8 region."""

    groups: int
    correctable: int
    uncorrectable: int
    first_bad_offset: int | None


@dataclass(frozen=True)
class XzStream:
    """Facts about the single xz stream at the start of a buffer."""

    check_type: int
    stream_length: int
    uncompressed_size: int
    block_filters: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class ElfSize:
    """BOOTKERNEL size as skiboot's ``sizeof_elf_from_hdr`` computes it."""

    elf_class: int
    elf_data: int
    e_shoff: int
    e_shentsize: int
    e_shnum: int

    @property
    def size(self) -> int:
        """Return ``e_shoff + e_shentsize * e_shnum``."""
        return self.e_shoff + self.e_shentsize * self.e_shnum


@dataclass(frozen=True)
class Fixtures:
    """The four live TOC blocks captured from compute-2."""

    live_a: Toc
    live_a_backup: Toc
    live_b: Toc
    live_b_backup: Toc


class Report:
    """Collects human-readable lines and violations for one run."""

    def __init__(self) -> None:
        """Start with no output and no violations."""
        self.lines: list[str] = []
        self.violations: list[str] = []

    def note(self, line: str) -> None:
        """Record an informational line."""
        self.lines.append(line)

    def fail(self, message: str) -> None:
        """Record a violation; any violation makes the run fail."""
        self.violations.append(message)
        self.lines.append(f"VIOLATION: {message}")

    def render(self) -> str:
        """Return the report text followed by a one-line verdict."""
        verdict = (
            "RESULT: PASS (0 violations)"
            if not self.violations
            else f"RESULT: FAIL ({len(self.violations)} violations)"
        )
        return "\n".join([*self.lines, verdict]) + "\n"


def _xor_words(raw: bytes) -> int:
    """Return the XOR of the big-endian 32-bit words in ``raw``."""
    value = 0
    for (word,) in struct.iter_unpack(">I", raw):
        value ^= word
    return value


def _hexrange(base: int, size: int) -> str:
    """Format a base/size pair the way the reports print it."""
    return f"0x{base:07x}/0x{size:07x}"


def parse_toc(image: bytes, offset: int) -> Toc:
    """Parse the FFS v1 TOC that starts at ``offset`` in ``image``.

    Structural defects that make the block unusable raise ``TocError``.
    Checksum mismatches, duplicate or malformed names and out-of-range
    entries are returned in ``Toc.problems`` so that every defect is
    reported, mirroring the checks skiboot's libffs applies before it
    trusts a TOC.
    """
    if offset < 0 or offset + FFS_HEADER_BYTES > len(image):
        raise TocError(f"TOC at 0x{offset:x} lies outside the image")
    header_raw = image[offset : offset + FFS_HEADER_BYTES]
    (
        magic,
        version,
        size_blocks,
        entry_size,
        entry_count,
        block_size,
        block_count,
        _r0,
        _r1,
        _r2,
        _r3,
        _checksum,
    ) = struct.unpack(FFS_HEADER_FORMAT, header_raw)
    if magic != FFS_MAGIC:
        raise TocError(f"TOC at 0x{offset:x}: magic 0x{magic:08x} is not 'PART'")
    if version != FFS_VERSION:
        raise TocError(f"TOC at 0x{offset:x}: version {version} is not {FFS_VERSION}")
    if entry_size != FFS_ENTRY_BYTES:
        raise TocError(f"TOC at 0x{offset:x}: entry size {entry_size} is not {FFS_ENTRY_BYTES}")
    if block_size == 0:
        raise TocError(f"TOC at 0x{offset:x}: block size is zero")
    toc_bytes = size_blocks * block_size
    needed = FFS_HEADER_BYTES + entry_count * entry_size
    if needed > toc_bytes:
        raise TocError(
            f"TOC at 0x{offset:x}: {entry_count} entries need {needed} bytes "
            f"but the TOC is {toc_bytes} bytes"
        )
    if offset + needed > len(image):
        raise TocError(f"TOC at 0x{offset:x}: entries run past the end of the image")

    problems: list[str] = []
    if _xor_words(header_raw) != 0:
        problems.append(f"TOC at 0x{offset:x}: header checksum mismatch")

    entries: list[TocEntry] = []
    seen: set[str] = set()
    for index in range(entry_count):
        start = offset + FFS_HEADER_BYTES + index * entry_size
        raw = image[start : start + entry_size]
        fields = struct.unpack(FFS_ENTRY_FORMAT, raw)
        name_raw: bytes = fields[0]
        terminator = name_raw.find(b"\x00")
        label = f"TOC at 0x{offset:x} entry {index}"
        if terminator < 0:
            problems.append(f"{label}: name is not NUL-terminated")
            name_bytes = name_raw
        else:
            name_bytes = name_raw[:terminator]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError:
            problems.append(f"{label}: name is not ASCII")
            name = name_bytes.decode("ascii", "backslashreplace")
        if not name or not name.isprintable():
            problems.append(f"{label}: name {name!r} is empty or unprintable")
        if _xor_words(raw) != 0:
            problems.append(f"{label} ({name}): entry checksum mismatch")
        if name in seen:
            problems.append(f"{label}: duplicate partition name {name}")
        seen.add(name)
        entry = TocEntry(
            name=name,
            base=fields[1] * block_size,
            size=fields[2] * block_size,
            pid=fields[3],
            entry_id=fields[4],
            entry_type=fields[5],
            flags=fields[6],
            actual=fields[7],
            chip=fields[12],
            compress_type=fields[13],
            data_integ=fields[14],
            ver_check=fields[15],
            misc_flags=fields[16],
        )
        if entry.end > block_count * block_size:
            problems.append(
                f"{label} ({name}): {_hexrange(entry.base, entry.size)} runs past "
                f"the flash ({block_count} blocks)"
            )
        entries.append(entry)

    return Toc(
        offset=offset,
        version=version,
        size_blocks=size_blocks,
        entry_size=entry_size,
        block_size=block_size,
        block_count=block_count,
        entries=tuple(entries),
        problems=tuple(problems),
    )


def ecc_generate(word: int) -> int:
    """Return the ECC byte for a 64-bit word (port of skiboot ``eccgenerate``)."""
    result = 0
    for bit, mask in enumerate(ECC_MATRIX):
        result |= ((mask & word).bit_count() & 1) << bit
    return result


def _ecc_byte_tables() -> tuple[tuple[int, ...], ...]:
    """Precompute per-byte ECC contributions; ECC is linear over XOR."""
    return tuple(
        tuple(ecc_generate(value << (56 - 8 * position)) for value in range(256))
        for position in range(8)
    )


_ECC_TABLES: Final = _ecc_byte_tables()


def ecc_encode(data: bytes) -> bytes:
    """Return ``data`` with one ECC byte after every 8 data bytes.

    This is the inverse of the scan and matches ``ecc --inject --p8`` from
    open-power/ffs; ``data`` must be a multiple of 8 bytes long.
    """
    if len(data) % 8:
        raise ValueError("ECC encoding needs a multiple of 8 data bytes")
    out = bytearray()
    for start in range(0, len(data), 8):
        chunk = data[start : start + 8]
        out += chunk
        out.append(ecc_generate(int.from_bytes(chunk, "big")))
    return bytes(out)


def ecc_scan(data: bytes) -> EccScan:
    """Check every 9-byte group of ``data`` against skiboot's syndrome table.

    Correctable single-bit errors and uncorrectable errors are counted
    separately; a freshly built image must have neither.
    """
    if len(data) % 9:
        raise ValueError("ECC data must be a multiple of 9 bytes")
    t0, t1, t2, t3, t4, t5, t6, t7 = _ECC_TABLES
    correctable = 0
    uncorrectable = 0
    first_bad: int | None = None
    for start in range(0, len(data), 9):
        b = data[start : start + 9]
        expected = (
            t0[b[0]] ^ t1[b[1]] ^ t2[b[2]] ^ t3[b[3]]
            ^ t4[b[4]] ^ t5[b[5]] ^ t6[b[6]] ^ t7[b[7]]
        )
        syndrome = SYNDROME_MATRIX[expected ^ b[8]]
        if syndrome == SYNDROME_GOOD:
            continue
        if syndrome == SYNDROME_UE:
            uncorrectable += 1
        else:
            correctable += 1
        if first_bad is None:
            first_bad = start
    return EccScan(
        groups=len(data) // 9,
        correctable=correctable,
        uncorrectable=uncorrectable,
        first_bad_offset=first_bad,
    )


def written_length(region: bytes, ecc: bool) -> int:
    """Return how many leading bytes of a partition were actually written.

    buildpnor truncates every partition's TOC ``actual`` to the full
    partition size, so ``actual`` says nothing about the data.  Flash that
    was never written reads as 0xFF; for an ECC partition the length is
    rounded up to whole 9-byte groups because a group of nine 0xFF bytes is
    never valid ECC (the ECC of eight 0xFF bytes is 0x00), while a group of
    written 0xFF data always carries a 0x00 ECC byte.
    """
    length = len(region.rstrip(b"\xff"))
    if ecc:
        return (length + 8) // 9 * 9
    return length


def _read_vli(data: bytes, pos: int, limit: int) -> tuple[int, int]:
    """Decode an xz variable-length integer at ``pos``; return value and end."""
    value = 0
    for index in range(9):
        if pos + index >= limit:
            raise XzError("truncated variable-length integer")
        byte = data[pos + index]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if byte == 0 and index:
                raise XzError("variable-length integer is not minimally encoded")
            return value, pos + index + 1
    raise XzError("variable-length integer is longer than 9 bytes")


def _crc32_ok(payload: bytes, stored: bytes) -> bool:
    """Return whether ``stored`` is the little-endian CRC32 of ``payload``."""
    return zlib.crc32(payload) == int.from_bytes(stored, "little")


def parse_xz(data: bytes) -> XzStream:
    """Parse the xz stream at the start of ``data`` without trusting it.

    The stream header, every block header, the index and the stream footer
    are walked by hand (xz-file-format 1.x) to collect the check type and
    the filter chain of each block, and the stream is decompressed with the
    standard library so that its integrity checks run as well.  Anything
    after the stream is ignored, exactly as hostboot's ``XZ_SINGLE`` decoder
    ignores the rest of the partition.
    """
    if len(data) < 24 or data[:6] != XZ_HEADER_MAGIC:
        raise XzError("no xz stream header magic")
    flags = data[6:8]
    if flags[0] != 0 or flags[1] & 0xF0:
        raise XzError("reserved stream flag bits are set")
    if not _crc32_ok(flags, data[8:12]):
        raise XzError("stream header CRC32 mismatch")
    check_type = flags[1] & 0x0F

    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    try:
        output = decompressor.decompress(data)
    except lzma.LZMAError as exc:
        raise XzError(f"decompression failed: {exc}") from exc
    if not decompressor.eof:
        raise XzError("stream is truncated (no end of stream before the data ends)")
    stream_length = len(data) - len(decompressor.unused_data)

    footer = data[stream_length - 12 : stream_length]
    if footer[10:12] != XZ_FOOTER_MAGIC:
        raise XzError("no xz stream footer magic")
    if not _crc32_ok(footer[4:10], footer[0:4]):
        raise XzError("stream footer CRC32 mismatch")
    if footer[8:10] != flags:
        raise XzError("stream footer flags differ from the header")
    backward_size = (int.from_bytes(footer[4:8], "little") + 1) * 4
    index_end = stream_length - 12
    index_start = index_end - backward_size
    if index_start < 12 or data[index_start] != 0x00:
        raise XzError("no index indicator where the footer points")

    pos = index_start + 1
    record_count, pos = _read_vli(data, pos, index_end)
    records: list[tuple[int, int]] = []
    for _ in range(record_count):
        unpadded, pos = _read_vli(data, pos, index_end)
        uncompressed, pos = _read_vli(data, pos, index_end)
        records.append((unpadded, uncompressed))
    while (pos - index_start) % 4:
        if pos >= index_end or data[pos] != 0:
            raise XzError("non-zero index padding")
        pos += 1
    if pos + 4 != index_end:
        raise XzError("index size does not match the footer's backward size")
    if not _crc32_ok(data[index_start:pos], data[pos : pos + 4]):
        raise XzError("index CRC32 mismatch")

    block_filters: list[tuple[int, ...]] = []
    block_pos = 12
    for unpadded, _uncompressed in records:
        if block_pos >= index_start:
            raise XzError(f"block {len(block_filters)} starts at or after the index")
        if data[block_pos] == 0:
            raise XzError(f"index indicator found where block {len(block_filters)} should start")
        header_size = (data[block_pos] + 1) * 4
        if block_pos + header_size > index_start or header_size > unpadded:
            raise XzError(f"block {len(block_filters)} header overruns the block")
        header = data[block_pos : block_pos + header_size]
        if not _crc32_ok(header[:-4], header[-4:]):
            raise XzError(f"block {len(block_filters)} header CRC32 mismatch")
        block_flags = header[1]
        if block_flags & 0x3C:
            raise XzError(f"block {len(block_filters)} sets reserved header flag bits")
        filter_count = (block_flags & 0x03) + 1
        hpos = 2
        hend = header_size - 4
        if block_flags & 0x40:
            _value, hpos = _read_vli(header, hpos, hend)
        if block_flags & 0x80:
            _value, hpos = _read_vli(header, hpos, hend)
        filters: list[int] = []
        for _ in range(filter_count):
            filter_id, hpos = _read_vli(header, hpos, hend)
            props_size, hpos = _read_vli(header, hpos, hend)
            hpos += props_size
            if hpos > hend:
                raise XzError(f"block {len(block_filters)} filter properties overrun the header")
            filters.append(filter_id)
        if any(header[hpos:hend]):
            raise XzError(f"block {len(block_filters)} header padding is not zero")
        block_filters.append(tuple(filters))
        block_pos += (unpadded + 3) & ~3
    if block_pos != index_start:
        raise XzError("blocks listed in the index do not end where the index starts")
    if sum(uncompressed for _unpadded, uncompressed in records) != len(output):
        raise XzError("index uncompressed sizes do not match the decompressed data")

    return XzStream(
        check_type=check_type,
        stream_length=stream_length,
        uncompressed_size=len(output),
        block_filters=tuple(block_filters),
    )


def elf_size(header: bytes) -> ElfSize:
    """Compute the BOOTKERNEL size the way skiboot's ``sizeof_elf_from_hdr`` does.

    skiboot ignores the TOC's actual size for BOOTKERNEL and reads exactly
    ``e_shoff + e_shentsize * e_shnum`` bytes, so an image whose section
    headers were stripped (``e_shoff == 0``) or that claims more than the
    partition holds cannot boot.
    """
    if header[:4] == STB_CONTAINER_MAGIC:
        raise ElfError("BOOTKERNEL starts with a secure-boot container, not an ELF image")
    if len(header) < 64 or header[:4] != ELF_MAGIC:
        raise ElfError("BOOTKERNEL does not start with an ELF header")
    elf_class = header[4]
    elf_data = header[5]
    if elf_data == 1:
        order = "<"
    elif elf_data == 2:
        order = ">"
    else:
        raise ElfError(f"ELF data encoding {elf_data} is neither LSB nor MSB")
    if elf_class == 2:
        (e_shoff,) = struct.unpack_from(order + "Q", header, 0x28)
        e_shentsize, e_shnum = struct.unpack_from(order + "HH", header, 0x3A)
    elif elf_class == 1:
        (e_shoff,) = struct.unpack_from(order + "I", header, 0x20)
        e_shentsize, e_shnum = struct.unpack_from(order + "HH", header, 0x2E)
    else:
        raise ElfError(f"ELF class {elf_class} is neither ELF32 nor ELF64")
    return ElfSize(
        elf_class=elf_class,
        elf_data=elf_data,
        e_shoff=e_shoff,
        e_shentsize=e_shentsize,
        e_shnum=e_shnum,
    )


def version_text(region: bytes) -> str:
    """Return the op-build version text held in a VERSION partition.

    update_image.pl pads the generated version file to 4 KiB with NUL
    bytes, so the text runs up to the first NUL and everything after it
    must be NUL.  The text must be printable ASCII (tabs and newlines
    allowed) and must not carry the markers op-build writes when it could
    not describe the tree it built from.
    """
    end = region.find(b"\x00")
    if end < 0:
        raise VersionError("VERSION has no NUL padding; the text fills or overruns the partition")
    if any(region[end:]):
        raise VersionError("VERSION has non-NUL bytes after the NUL-terminated text")
    raw = region[:end]
    if not raw.strip():
        raise VersionError("VERSION is empty")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VersionError("VERSION text is not ASCII") from exc
    if any(not (char.isprintable() or char in "\t\n") for char in text):
        raise VersionError("VERSION text contains control characters")
    for line in text.splitlines():
        for pattern, meaning in VERSION_FORBIDDEN:
            if pattern.search(line):
                raise VersionError(f"VERSION line {line.strip()!r} contains {meaning}")
    return text


def _parse_sums(path: Path) -> dict[str, str]:
    """Parse a ``sha256sum``-style file into a name-to-digest mapping."""
    sums: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line)
        if match is None:
            raise FixtureError(f"{path}:{number}: not a sha256sum line")
        sums[match.group(2)] = match.group(1)
    return sums


def load_fixtures(directory: Path) -> Fixtures:
    """Load and authenticate the four live TOC blocks from ``directory``.

    Each block must be exactly 4 KiB, match the digest recorded in the
    directory's SHA256SUMS and parse without a single problem.
    """
    sums_path = directory / FIXTURE_SUMS
    if not sums_path.is_file():
        raise FixtureError(f"{sums_path} is missing")
    sums = _parse_sums(sums_path)
    tocs: list[Toc] = []
    for name in FIXTURE_NAMES:
        path = directory / name
        if not path.is_file():
            raise FixtureError(f"{path} is missing")
        raw = path.read_bytes()
        if name not in sums:
            raise FixtureError(f"{sums_path} has no digest for {name}")
        if hashlib.sha256(raw).hexdigest() != sums[name]:
            raise FixtureError(f"{path} does not match its digest in {sums_path}")
        if len(raw) != TOC_BLOCK_BYTES:
            raise FixtureError(f"{path} is {len(raw)} bytes, not {TOC_BLOCK_BYTES}")
        try:
            toc = parse_toc(raw, 0)
        except TocError as exc:
            raise FixtureError(f"{path}: {exc}") from exc
        if toc.problems:
            raise FixtureError(f"{path}: {'; '.join(toc.problems)}")
        tocs.append(toc)
    return Fixtures(
        live_a=tocs[0],
        live_a_backup=tocs[1],
        live_b=tocs[2],
        live_b_backup=tocs[3],
    )


def _toc_geometry(report: Report, toc: Toc, label: str) -> None:
    """Assert the geometry every side-A TOC must have."""
    for problem in toc.problems:
        report.fail(f"{label}: {problem}")
    if toc.block_size != BLOCK_SIZE:
        report.fail(f"{label}: block size 0x{toc.block_size:x} is not 0x{BLOCK_SIZE:x}")
    if toc.block_count * toc.block_size != IMAGE_SIZE:
        report.fail(
            f"{label}: block count {toc.block_count} x 0x{toc.block_size:x} "
            f"is not the 0x{IMAGE_SIZE:x}-byte flash"
        )
    if toc.size_blocks * toc.block_size != TOC_BLOCK_BYTES:
        report.fail(
            f"{label}: TOC occupies {toc.size_blocks} blocks; the kit ships exactly "
            f"one 0x{TOC_BLOCK_BYTES:x}-byte block"
        )


def _pointer(report: Report, toc: Toc, label: str, name: str, expected: int) -> None:
    """Assert that the TOC entry ``name`` points at ``expected``."""
    entry = toc.find(name)
    if entry is None:
        report.fail(f"{label}: no {name} entry")
    elif entry.base != expected:
        report.fail(f"{label}: {name} points at 0x{entry.base:x}, expected 0x{expected:x}")


def _check_backup_matches(report: Report, primary: Toc, backup: Toc) -> None:
    """Assert the backup TOC lists exactly the primary's partitions.

    Every field that places or describes a partition must agree.  ``actual``
    is left out because it records how much was written, which flash tools
    may update through one TOC only; it never moves a partition.
    """
    names_primary = primary.names() - set(TOC_ENTRY_NAMES)
    names_backup = backup.names() - set(TOC_ENTRY_NAMES)
    for name in sorted(names_primary - names_backup):
        report.fail(f"backup TOC at 0x{BACKUP_TOC:x} lacks {name}")
    for name in sorted(names_backup - names_primary):
        report.fail(f"backup TOC at 0x{BACKUP_TOC:x} has extra partition {name}")
    for name in sorted(names_primary & names_backup):
        first = primary.find(name)
        second = backup.find(name)
        if first is not None and second is not None and first.identity() != second.identity():
            report.fail(
                f"backup TOC entry {name} ({_hexrange(second.base, second.size)}, "
                f"integ 0x{second.data_integ:04x}, misc 0x{second.misc_flags:02x}) differs "
                f"from the primary ({_hexrange(first.base, first.size)}, "
                f"integ 0x{first.data_integ:04x}, misc 0x{first.misc_flags:02x})"
            )


def _check_data_partitions(report: Report, new: Toc, fixtures: Fixtures) -> None:
    """Assert every shared/data and untouched live partition is exactly where and what it is live."""
    for name in (*DATA_PARTITIONS, *UNTOUCHED_LIVE_PARTITIONS):
        live = fixtures.live_a.find(name)
        entry = new.find(name)
        if live is None:
            report.fail(f"live side-A fixture has no {name}; the fixture is not compute-2's")
            continue
        if entry is None:
            report.fail(f"data partition {name} is missing from the new side-A TOC")
            continue
        if entry.identity() != live.identity():
            report.fail(
                f"data partition {name} changed: live {_hexrange(live.base, live.size)} "
                f"{_flags_text(live)}, new {_hexrange(entry.base, entry.size)} "
                f"{_flags_text(entry)}"
            )
        for label, side_b in (
            (FIXTURE_LIVE_B, fixtures.live_b),
            (FIXTURE_LIVE_B_BACKUP, fixtures.live_b_backup),
        ):
            shared = side_b.find(name)
            if shared is not None and (shared.base, shared.size) != (entry.base, entry.size):
                report.fail(
                    f"data partition {name} at {_hexrange(entry.base, entry.size)} no longer "
                    f"matches the copy side B references in {label} "
                    f"({_hexrange(shared.base, shared.size)})"
                )


def _flags_text(entry: TocEntry) -> str:
    """Format the TOC fields that decide how a partition is treated."""
    return (
        f"type {entry.entry_type} flags 0x{entry.flags:x} integ 0x{entry.data_integ:04x} "
        f"vercheck 0x{entry.ver_check:02x} misc 0x{entry.misc_flags:02x}"
    )


def _expected_code_layout(live: Toc) -> dict[str, TocEntry]:
    """Derive the decided side-A code partitions from the live TOC.

    Every live code partition keeps its base, size and flags except HBD,
    which is split into HBD and HBD_RW within its old footprint, both
    keeping the live HBD's flags, and the untouched TEST partition, which
    master-p8 buildpnor still emits identical to live but which is never
    written.  Without a live HBD the split
    partitions are left out, which the caller reports as a fixture that
    does not describe compute-2.
    """
    layout: dict[str, TocEntry] = {}
    for entry in live.entries:
        if entry.name in TOC_ENTRY_NAMES or entry.name in DATA_PARTITIONS:
            continue
        if entry.name in UNTOUCHED_LIVE_PARTITIONS:
            continue
        layout[entry.name] = entry
    hbd = layout.get("HBD")
    if hbd is not None:
        for name, (base, size) in SPLIT_PARTITIONS.items():
            layout[name] = replace(hbd, name=name, base=base, size=size)
    return layout


def _check_code_partitions(report: Report, new: Toc, fixtures: Fixtures) -> list[TocEntry]:
    """Assert the side-A code partitions are the decided set, placed and flagged as decided."""
    names = new.names()
    unexpected = (
        names
        - set(TOC_ENTRY_NAMES)
        - set(DATA_PARTITIONS)
        - set(UNTOUCHED_LIVE_PARTITIONS)
        - set(CODE_PARTITIONS)
    )
    for name in sorted(unexpected):
        report.fail(f"unexpected partition {name} in the new side-A TOC")
    for name in CODE_PARTITIONS:
        if name not in names:
            report.fail(f"code partition {name} is missing from the new side-A TOC")

    expected = _expected_code_layout(fixtures.live_a)
    if set(expected) != set(CODE_PARTITIONS):
        report.fail(
            "live fixture code partitions "
            f"{sorted(expected)} do not match the expected set {sorted(CODE_PARTITIONS)}"
        )

    code = sorted(
        (entry for entry in new.entries if entry.name in CODE_PARTITIONS),
        key=lambda entry: entry.base,
    )
    protected: dict[tuple[str, int, int], TocEntry] = {}
    for entry in [*new.entries, *fixtures.live_a.entries]:
        if (
            entry.name in DATA_PARTITIONS
            or entry.name in UNTOUCHED_LIVE_PARTITIONS
            or entry.name == "BACKUP_PART"
        ):
            protected[(entry.name, entry.base, entry.size)] = entry

    for entry in code:
        if entry.size == 0:
            report.fail(f"code partition {entry.name} has zero size")
        if entry.base < CODE_REGION_START or entry.end > CODE_REGION_END:
            report.fail(
                f"code partition {entry.name} {_hexrange(entry.base, entry.size)} is outside "
                f"side A's code region 0x{CODE_REGION_START:x}..0x{CODE_REGION_END:x}"
            )
        for other in protected.values():
            if entry.base < other.end and other.base < entry.end:
                report.fail(
                    f"code partition {entry.name} {_hexrange(entry.base, entry.size)} overlaps "
                    f"{other.name} {_hexrange(other.base, other.size)}"
                )
        want = expected.get(entry.name)
        if want is not None and (want.base, want.size) != (entry.base, entry.size):
            report.fail(
                f"code partition {entry.name} is at {_hexrange(entry.base, entry.size)}, the "
                f"decided layout puts it at {_hexrange(want.base, want.size)}"
            )
        elif want is not None and want.identity() != entry.identity():
            report.fail(
                f"code partition {entry.name} changed flags: decided layout "
                f"{_flags_text(want)}, new {_flags_text(entry)}"
            )
        fixed = FIXED_PARTITIONS.get(entry.name)
        if fixed is not None and fixed != (entry.base, entry.size):
            report.fail(
                f"{entry.name} must be exactly {_hexrange(fixed[0], fixed[1])}, "
                f"found {_hexrange(entry.base, entry.size)}"
            )
        if entry.actual > entry.size:
            report.fail(
                f"code partition {entry.name} claims an actual size of {entry.actual} bytes "
                f"in a {entry.size}-byte partition"
            )

    for first, second in zip(code, code[1:]):
        if second.base < first.end:
            report.fail(
                f"code partitions {first.name} {_hexrange(first.base, first.size)} and "
                f"{second.name} {_hexrange(second.base, second.size)} overlap"
            )

    hbb = new.find("HBB")
    if hbb is not None and hbb.base != HBB_BASE:
        report.fail(
            f"HBB moved to 0x{hbb.base:x}; the SBE SEEPROM points at 0x{HBB_BASE:x}"
        )
    return code


def _region(image: bytes, entry: TocEntry) -> bytes:
    """Return the full partition slice of ``entry`` from ``image``."""
    return image[entry.base : entry.end]


def _check_written(report: Report, image: bytes, code: list[TocEntry]) -> dict[str, int]:
    """Assert every code partition carries data; return the written lengths."""
    lengths: dict[str, int] = {}
    for entry in code:
        region = _region(image, entry)
        length = written_length(region, entry.ecc)
        if length == 0:
            report.fail(f"code partition {entry.name} is entirely erased (no content written)")
        lengths[entry.name] = length
    return lengths


def _check_ecc(report: Report, image: bytes, new: Toc) -> None:
    """Run the ECC syndrome scan over every ECC partition's written bytes.

    The written bytes run from the partition base to the last 9-byte group
    that is not erased flash; inside that span every group must be clean.
    """
    for entry in sorted(new.entries, key=lambda item: item.base):
        if not entry.ecc or entry.name in TOC_ENTRY_NAMES:
            continue
        region = _region(image, entry)
        length = written_length(region, True)
        if length > len(region):
            report.fail(
                f"ECC partition {entry.name}: data reaches the last "
                f"{len(region) % 9} bytes, which cannot hold a whole 9-byte ECC group"
            )
            continue
        scan = ecc_scan(region[:length])
        if scan.correctable or scan.uncorrectable:
            where = (
                f" first at 0x{entry.base + scan.first_bad_offset:x}"
                if scan.first_bad_offset is not None
                else ""
            )
            report.fail(
                f"ECC partition {entry.name}: {scan.uncorrectable} uncorrectable and "
                f"{scan.correctable} correctable groups out of {scan.groups} written{where}"
            )
        else:
            report.note(
                f"  ECC {entry.name:<12} {scan.groups} written groups clean "
                f"(0x{length:x} of 0x{entry.size:x} bytes)"
            )


def _check_payload(report: Report, image: bytes, new: Toc) -> None:
    """Validate PAYLOAD as hostboot master-p8 loads it (xz, CRC32, LZMA2 only)."""
    entry = new.find("PAYLOAD")
    if entry is None:
        return
    if entry.ecc:
        report.fail("PAYLOAD is flagged ECC; hostboot loads it raw")
        return
    try:
        stream = parse_xz(_region(image, entry))
    except XzError as exc:
        report.fail(f"PAYLOAD: {exc}")
        return
    check_name = XZ_CHECK_NAMES.get(stream.check_type, f"0x{stream.check_type:x}")
    if stream.check_type != XZ_CHECK_CRC32:
        report.fail(f"PAYLOAD xz check is {check_name}; hostboot's xz-embedded only has CRC32")
    for index, filters in enumerate(stream.block_filters):
        if filters != (XZ_FILTER_LZMA2,):
            names = ", ".join(f"0x{filter_id:x}" for filter_id in filters)
            report.fail(
                f"PAYLOAD xz block {index} uses filters [{names}]; only LZMA2 (0x21) is allowed"
            )
    bound = entry.size * HOSTBOOT_XZ_RATIO
    if stream.uncompressed_size > bound:
        report.fail(
            f"PAYLOAD decompresses to {stream.uncompressed_size} bytes, beyond hostboot's "
            f"{HOSTBOOT_XZ_RATIO}x bound of {bound}"
        )
    report.note(
        f"  PAYLOAD xz: {stream.stream_length} of {entry.size} bytes "
        f"({entry.size - stream.stream_length} free), check {check_name}, "
        f"{len(stream.block_filters)} block(s), {stream.uncompressed_size} bytes uncompressed "
        f"(bound {bound})"
    )


def _check_bootkernel(report: Report, image: bytes, new: Toc) -> None:
    """Validate BOOTKERNEL as skiboot loads it (ELF size from the header)."""
    entry = new.find("BOOTKERNEL")
    if entry is None:
        return
    if entry.ecc:
        report.fail("BOOTKERNEL is flagged ECC; skiboot loads it raw")
        return
    region = _region(image, entry)
    try:
        elf = elf_size(region[:64])
    except ElfError as exc:
        report.fail(f"BOOTKERNEL: {exc}")
        return
    if elf.e_shoff == 0:
        report.fail("BOOTKERNEL ELF has e_shoff == 0; skiboot would compute a size of zero")
        return
    if elf.size > entry.size:
        report.fail(
            f"BOOTKERNEL ELF size {elf.size} (e_shoff 0x{elf.e_shoff:x} + "
            f"{elf.e_shentsize} x {elf.e_shnum}) exceeds the 0x{entry.size:x}-byte partition"
        )
        return
    section_headers = region[elf.e_shoff : elf.size]
    if not section_headers.strip(b"\xff"):
        report.fail(
            f"BOOTKERNEL section headers at 0x{elf.e_shoff:x}..0x{elf.size:x} read as erased "
            "flash; the image was truncated"
        )
    written = written_length(region, False)
    report.note(
        f"  BOOTKERNEL ELF{32 if elf.elf_class == 1 else 64} "
        f"{'LSB' if elf.elf_data == 1 else 'MSB'}: {elf.size} of {entry.size} bytes "
        f"({entry.size - elf.size} free, {100 * elf.size / entry.size:.1f}% used, "
        f"{written} bytes written; live skiroot is {LIVE_BOOTKERNEL_ELF_SIZE}, "
        f"delta {elf.size - LIVE_BOOTKERNEL_ELF_SIZE:+d})"
    )


def _check_version(report: Report, image: bytes, new: Toc) -> None:
    """Validate the VERSION partition text that petitboot and the BMC show."""
    entry = new.find("VERSION")
    if entry is None:
        return
    try:
        text = version_text(_region(image, entry))
    except VersionError as exc:
        report.fail(str(exc))
        return
    report.note(f"  VERSION: {text.splitlines()[0].strip()}")


def _check_identical(report: Report, image: bytes, new: Toc, name: str, path: Path) -> None:
    """Assert that partition ``name`` starts with exactly the bytes of ``path``."""
    entry = new.find(name)
    if entry is None:
        return
    blob = path.read_bytes()
    if len(blob) > entry.size:
        report.fail(
            f"{name}: build output {path.name} is {len(blob)} bytes, larger than the "
            f"0x{entry.size:x}-byte partition"
        )
        return
    if image[entry.base : entry.base + len(blob)] != blob:
        report.fail(f"{name}: partition content differs from build output {path.name}")
        return
    report.note(f"  {name} carries {path.name} byte for byte ({len(blob)} bytes)")


def _diff_lines(new: Toc, live: Toc) -> list[str]:
    """Render the new side-A TOC against the live one, ordered by address."""
    bases = {entry.name: entry.base for entry in live.entries}
    bases.update({entry.name: entry.base for entry in new.entries})
    names = sorted(bases, key=lambda name: (bases[name], name))
    lines = [
        f"TOC diff: new side A (0x{PRIMARY_TOC:x}) against live {FIXTURE_LIVE_A}",
        f"  {'name':<12} {'live base/size':<20} {'new base/size':<20} {'ecc':<5} "
        f"{'misc live/new':<14} {'actual':<10} status",
    ]
    for name in names:
        old = live.find(name)
        cur = new.find(name)
        old_range = _hexrange(old.base, old.size) if old else "-"
        cur_range = _hexrange(cur.base, cur.size) if cur else "-"
        ecc = f"{'y' if old and old.ecc else ('n' if old else '-')}/" + (
            "y" if cur and cur.ecc else ("n" if cur else "-")
        )
        misc = f"{f'0x{old.misc_flags:02x}' if old else '-'}/" + (
            f"0x{cur.misc_flags:02x}" if cur else "-"
        )
        actual = f"0x{cur.actual:x}" if cur else "-"
        if name in TOC_ENTRY_NAMES:
            status = "toc"
        elif old is None:
            status = "added"
        elif cur is None:
            status = "removed"
        elif name in DATA_PARTITIONS:
            status = "data, preserved" if old.identity() == cur.identity() else "DATA CHANGED"
        elif name in UNTOUCHED_LIVE_PARTITIONS:
            status = "untouched" if old.identity() == cur.identity() else "UNTOUCHED CHANGED"
        elif (old.base, old.size) != (cur.base, cur.size):
            status = "moved/resized"
        elif old.identity() != cur.identity():
            status = "flags changed"
        else:
            status = "same place"
        lines.append(
            f"  {name:<12} {old_range:<20} {cur_range:<20} {ecc:<5} {misc:<14} {actual:<10} {status}"
        )
    return lines


def run_check(
    image: bytes,
    fixtures_dir: Path,
    payload: Path | None = None,
    bootkernel: Path | None = None,
) -> tuple[Report, Toc | None]:
    """Run every safety assertion; return the report and the new side-A TOC.

    ``payload`` and ``bootkernel`` name build outputs that the PAYLOAD and
    BOOTKERNEL partitions must start with; when given, a mismatch is a
    violation.
    """
    report = Report()
    try:
        fixtures = load_fixtures(fixtures_dir)
    except FixtureError as exc:
        report.fail(f"fixtures: {exc}")
        return report, None
    report.note(f"Fixtures: {fixtures_dir} (SHA256SUMS verified)")

    if len(image) != IMAGE_SIZE:
        report.fail(f"image is {len(image)} bytes, expected 0x{IMAGE_SIZE:x}")
        return report, None

    tocs: dict[int, Toc] = {}
    for offset, label in (
        (PRIMARY_TOC, "primary side-A TOC"),
        (BACKUP_TOC, "backup side-A TOC"),
        (OTHER_SIDE_TOC, "side-B TOC"),
    ):
        try:
            tocs[offset] = parse_toc(image, offset)
        except TocError as exc:
            report.fail(f"{label}: {exc}")
    primary = tocs.get(PRIMARY_TOC)
    backup = tocs.get(BACKUP_TOC)
    side_b = tocs.get(OTHER_SIDE_TOC)
    if primary is None:
        return report, None

    _toc_geometry(report, primary, "primary side-A TOC")
    _pointer(report, primary, "primary side-A TOC", "part", PRIMARY_TOC)
    _pointer(report, primary, "primary side-A TOC", "BACKUP_PART", BACKUP_TOC)
    _pointer(report, primary, "primary side-A TOC", "OTHER_SIDE", OTHER_SIDE_TOC)
    live_backup_ptr = fixtures.live_a.find("BACKUP_PART")
    live_other_ptr = fixtures.live_a.find("OTHER_SIDE")
    if live_backup_ptr is None or live_backup_ptr.base != BACKUP_TOC:
        report.fail(f"{FIXTURE_LIVE_A} does not point BACKUP_PART at 0x{BACKUP_TOC:x}")
    if live_other_ptr is None or live_other_ptr.base != OTHER_SIDE_TOC:
        report.fail(f"{FIXTURE_LIVE_A} does not point OTHER_SIDE at 0x{OTHER_SIDE_TOC:x}")

    if backup is not None:
        _toc_geometry(report, backup, "backup side-A TOC")
        _pointer(report, backup, "backup side-A TOC", "part", BACKUP_TOC)
        for name in ("BACKUP_PART", "OTHER_SIDE"):
            live = fixtures.live_a_backup.find(name)
            if live is None:
                report.fail(f"{FIXTURE_LIVE_A_BACKUP} has no {name}")
            else:
                _pointer(report, backup, "backup side-A TOC", name, live.base)
        _check_backup_matches(report, primary, backup)

    if side_b is not None:
        for problem in side_b.problems:
            report.fail(f"side-B TOC: {problem}")
        part = side_b.find("part")
        golden = part is not None and bool(part.misc_flags & 0x01)
        report.note(
            f"Side-B TOC at 0x{OTHER_SIDE_TOC:x}: {len(side_b.entries)} entries, "
            f"golden flag {'set' if golden else 'clear'} (built side B is never flashed)"
        )

    _check_data_partitions(report, primary, fixtures)
    code = _check_code_partitions(report, primary, fixtures)
    lengths = _check_written(report, image, code)

    report.note("")
    report.lines.extend(_diff_lines(primary, fixtures.live_a))
    report.note("")
    report.note("Content checks:")
    _check_ecc(report, image, primary)
    _check_payload(report, image, primary)
    _check_bootkernel(report, image, primary)
    _check_version(report, image, primary)
    if payload is not None:
        _check_identical(report, image, primary, "PAYLOAD", payload)
    if bootkernel is not None:
        _check_identical(report, image, primary, "BOOTKERNEL", bootkernel)
    report.note("")
    report.note("Side-A code partitions (headroom by written bytes, erased tail excluded):")
    for entry in code:
        used = lengths[entry.name]
        misc = ",".join(entry.misc_names())
        report.note(
            f"  {entry.name:<12} {_hexrange(entry.base, entry.size)} written 0x{used:07x} "
            f"free 0x{max(entry.size - used, 0):07x} ({100 * used / entry.size:5.1f}% used) "
            f"ecc {'y' if entry.ecc else 'n'} misc 0x{entry.misc_flags:02x}"
            f"{f' ({misc})' if misc else ''}"
        )
    return report, primary


def _sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def write_kit(image: bytes, new: Toc, out: Path) -> list[str]:
    """Write the side-A kit for an image that already passed ``run_check``.

    Returns the list of files written, in the order recorded in SHA256SUMS.
    """
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} exists and is not empty")
    version_entry = new.find("VERSION")
    if version_entry is None:
        raise VersionError("the side-A TOC has no VERSION partition")
    version = version_text(_region(image, version_entry))
    out.mkdir(parents=True, exist_ok=True)

    written: list[tuple[str, bytes]] = []
    tocs: list[TocBlockRecord] = []
    for filename, base in (("toc0.bin", PRIMARY_TOC), ("toc1.bin", BACKUP_TOC)):
        blob = image[base : base + TOC_BLOCK_BYTES]
        written.append((filename, blob))
        tocs.append(TocBlockRecord(file=filename, base=base, size=TOC_BLOCK_BYTES, sha256=_sha256(blob)))

    partitions: list[PartitionRecord] = []
    for entry in sorted(new.entries, key=lambda item: item.base):
        if entry.name not in CODE_PARTITIONS:
            continue
        filename = f"{entry.name}.bin"
        blob = _region(image, entry)
        written.append((filename, blob))
        partitions.append(
            PartitionRecord(
                name=entry.name,
                file=filename,
                base=entry.base,
                size=entry.size,
                actual=entry.actual,
                written=written_length(blob, entry.ecc),
                ecc=entry.ecc,
                flags=PartitionFlags(
                    ffs_flags=entry.flags,
                    chip=entry.chip,
                    compress_type=entry.compress_type,
                    data_integ=entry.data_integ,
                    ver_check=entry.ver_check,
                    misc_flags=entry.misc_flags,
                    misc=entry.misc_names(),
                ),
                sha256=_sha256(blob),
            )
        )

    preserve = [
        PreservedRecord(name=entry.name, base=entry.base, size=entry.size, ecc=entry.ecc)
        for entry in sorted(new.entries, key=lambda item: item.base)
        if entry.name in DATA_PARTITIONS or entry.name in UNTOUCHED_LIVE_PARTITIONS
    ]
    manifest = Manifest(
        format=1,
        description=(
            "Side-A kit for compute-2 (8335-GCA Firestone): toc0.bin belongs at 0x0, "
            "toc1.bin at 0x1FF8000 and every partition file at its base; the write order is "
            "the flashing procedure's decision. Never write anything listed in do_not_write "
            "or anywhere at or above 0x2000000."
        ),
        version=version,
        image=ImageRecord(size=len(image), sha256=_sha256(image)),
        tocs=tocs,
        partitions=partitions,
        do_not_write=preserve,
    )
    written.append(("VERSION", version.encode("ascii")))
    written.append(("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode("ascii")))

    for filename, blob in written:
        (out / filename).write_bytes(blob)
    sums = "".join(f"{_sha256(blob)}  {filename}\n" for filename, blob in written)
    (out / "SHA256SUMS").write_text(sums, encoding="ascii")
    return [filename for filename, _blob in written]


def parse_init_flags(source: str) -> tuple[int, list[tuple[str, int]]]:
    """Extract ``INIT_FLAG_ENABLED`` and the ``initFlagArray`` table from C++ source."""
    enabled_match = re.search(r"\bINIT_FLAG_ENABLED\s*=\s*(0x[0-9A-Fa-f]+)", source)
    if enabled_match is None:
        raise ValueError("INIT_FLAG_ENABLED is not defined")
    table_match = re.search(r"\binitFlagArray\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;", source, re.DOTALL)
    if table_match is None:
        raise ValueError("initFlagArray is not defined")
    body = table_match.group(1) + "}"
    entries = [
        (match.group(1), int(match.group(2), 0))
        for match in re.finditer(r'\{\s*"([^"]+)"\s*,\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*\}', body)
    ]
    if len(entries) != body.count("{"):
        raise ValueError("initFlagArray contains entries this parser does not understand")
    return int(enabled_match.group(1), 16), entries


def run_fwfeatures(source: str) -> Report:
    """Assert the fw-features hostboot master-p8 reports match the measured truth."""
    report = Report()
    try:
        enabled_bit, entries = parse_init_flags(source)
    except ValueError as exc:
        report.fail(str(exc))
        return report
    if enabled_bit != INIT_FLAG_ENABLED:
        report.fail(f"INIT_FLAG_ENABLED is 0x{enabled_bit:x}, expected 0x{INIT_FLAG_ENABLED:x}")
    counts: dict[str, int] = {}
    for name, _settings in entries:
        counts[name] = counts.get(name, 0) + 1
    for name, count in counts.items():
        if count > 1:
            report.fail(f"{name} appears {count} times in initFlagArray")
    report.note("initFlagArray:")
    states = {name: bool(settings & enabled_bit) for name, settings in entries}
    for name, settings in entries:
        report.note(f"  {name:<44} {'enabled' if settings & enabled_bit else 'disabled'}")
    for name, want in FW_FEATURE_EXPECTATIONS:
        if name not in states:
            report.fail(f"{name} is missing from initFlagArray")
        elif states[name] != want:
            report.fail(
                f"{name} is {'enabled' if states[name] else 'disabled'}, "
                f"expected {'enabled' if want else 'disabled'}"
            )
    return report


def _path_arg(namespace: argparse.Namespace, name: str) -> Path:
    """Fetch a ``Path`` argument from an argparse namespace with a precise type."""
    value: object = getattr(namespace, name)
    if not isinstance(value, Path):
        raise TypeError(f"argument {name} is not a path")
    return value


def _optional_path_arg(namespace: argparse.Namespace, name: str) -> Path | None:
    """Fetch an optional ``Path`` argument from an argparse namespace."""
    value: object = getattr(namespace, name)
    if value is None:
        return None
    if not isinstance(value, Path):
        raise TypeError(f"argument {name} is not a path")
    return value


def _str_arg(namespace: argparse.Namespace, name: str) -> str:
    """Fetch a ``str`` argument from an argparse namespace with a precise type."""
    value: object = getattr(namespace, name)
    if not isinstance(value, str):
        raise TypeError(f"argument {name} is not a string")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description="Check a Firestone PNOR image against compute-2's live layout and cut the side-A kit."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser("check", help="validate an image against the live TOC fixtures")
    kit_parser = commands.add_parser("kit", help="validate an image and write the side-A kit")
    for sub in (check_parser, kit_parser):
        sub.add_argument("image", type=Path)
        sub.add_argument("--fixtures", type=Path, required=True)
        sub.add_argument("--payload", type=Path, help="build output PAYLOAD must start with")
        sub.add_argument("--bootkernel", type=Path, help="build output BOOTKERNEL must start with")
    kit_parser.add_argument("--out", type=Path, required=True)
    fw_parser = commands.add_parser("fwfeatures", help="check hostboot's fw-features table")
    fw_parser.add_argument("source", type=Path)
    args = parser.parse_args(argv)
    command = _str_arg(args, "command")

    if command == "fwfeatures":
        report = run_fwfeatures(_path_arg(args, "source").read_text(encoding="utf-8"))
        sys.stdout.write(report.render())
        return 1 if report.violations else 0

    image = _path_arg(args, "image").read_bytes()
    report, new = run_check(
        image,
        _path_arg(args, "fixtures"),
        payload=_optional_path_arg(args, "payload"),
        bootkernel=_optional_path_arg(args, "bootkernel"),
    )
    sys.stdout.write(report.render())
    if report.violations or new is None:
        return 1
    if command == "kit":
        out = _path_arg(args, "out")
        files = write_kit(image, new, out)
        sys.stdout.write(f"Kit written to {out}: {', '.join(files)}, SHA256SUMS\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

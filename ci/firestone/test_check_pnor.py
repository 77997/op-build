#!/usr/bin/env python3
"""Unit tests for check_pnor.py.

The image tests synthesise a 64 MiB image from the committed live TOC
fixtures plus the decided new side-A TOC (the live layout with HBD split
into HBD and HBD_RW, TEST untouched), then break exactly one thing and
prove that the matching assertion fires.  The ECC port is checked against
skiboot's own test vectors and the fw-features guard against hostboot
master-p8's table.  Run with ``python3 -m unittest discover -s
ci/firestone`` from the repository root or ``python3 -m unittest`` from
this directory.  Setting ``FIRESTONE_LIVE_PNOR`` to a private dump of
compute-2's flash additionally validates the parser and the ECC port
against real data; nothing from that dump is ever written anywhere.
"""

import contextlib
import dataclasses
import hashlib
import io
import json
import lzma
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import check_pnor as cp

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
SYNTHETIC_VERSION = (
    b"open-power-firestone-v2.7-123-g0123456789\n"
    b"\tbuildroot-2025.02.18-1-ga872efdc\n"
    b"\tskiboot-v7.1-157-g0c32c70b\n"
    b"\thostboot-p8-3267aff\n"
)

MASTER_P8_INIT_FLAGS = """
enum
{
    INIT_FLAG_ENABLED   = 0x8000000000000000,
};

struct initFlags_t
{
    char     name[64];
    uint64_t settings;
}__attribute__ ((packed));

const initFlags_t initFlagArray[]=
{
{"tm-suspend-mode",                             0x8000000000000000},
{"inst-thread-reconfig-control-trig0-1",        0x0000000000000000},
{"fw-count-cache-disabled",                     0x8000000000000000},
{"inst-l1d-flush-trig2",                        0x0000000000000000},
{"inst-l1d-flush-ori30,30,0",                   0x8000000000000000},
{"inst-spec-barrier-ori31,31,0",                0x8000000000000000},
{"needs-l1d-flush-msr-hv-1-to-0",               0x8000000000000000},
{"needs-l1d-flush-msr-pr-0-to-1",               0x8000000000000000},
{"needs-spec-barrier-for-bound-checks",         0x8000000000000000},
{"fw-l1d-thread-split",                         0x0000000000000000},
{"fw-bcctrl-serialized",                        0x0000000000000000},
{"speculation-policy-favor-security",           0x8000000000000000}};
"""


def _checksummed(words: tuple[int, ...]) -> tuple[int, ...]:
    """Return ``words`` with the last word set so that all words XOR to zero."""
    value = 0
    for word in words[:-1]:
        value ^= word
    return (*words[:-1], value)


def serialise_toc(entries: list[cp.TocEntry], size_blocks: int = 1) -> bytes:
    """Serialise entries into one 4 KiB FFS v1 TOC block with valid checksums."""
    header_words = _checksummed(
        (cp.FFS_MAGIC, cp.FFS_VERSION, size_blocks, cp.FFS_ENTRY_BYTES, len(entries),
         cp.BLOCK_SIZE, cp.IMAGE_SIZE // cp.BLOCK_SIZE, 0, 0, 0, 0, 0)
    )
    out = bytearray(struct.pack(cp.FFS_HEADER_FORMAT, *header_words))
    for entry in entries:
        raw = struct.pack(
            cp.FFS_ENTRY_FORMAT,
            entry.name.encode("ascii"),
            entry.base // cp.BLOCK_SIZE,
            entry.size // cp.BLOCK_SIZE,
            entry.pid,
            entry.entry_id,
            entry.entry_type,
            entry.flags,
            entry.actual,
            0, 0, 0, 0,
            entry.chip,
            entry.compress_type,
            entry.data_integ,
            entry.ver_check,
            entry.misc_flags,
            b"\x00\x00",
            *([0] * 14),
            0,
        )
        words = _checksummed(struct.unpack(">32I", raw))
        out += struct.pack(">32I", *words)
    out += b"\xff" * (cp.TOC_BLOCK_BYTES - len(out))
    return bytes(out)


def decided_side_a_entries() -> list[cp.TocEntry]:
    """Build the new side-A TOC that the decided layout should produce."""
    live = cp.parse_toc((FIXTURES / cp.FIXTURE_LIVE_A).read_bytes(), 0)
    entries: list[cp.TocEntry] = []
    for entry in live.entries:
        if entry.name == "part":
            entry = dataclasses.replace(entry, misc_flags=0x40)
        elif entry.name in ("BACKUP_PART", "OTHER_SIDE"):
            entry = dataclasses.replace(entry, misc_flags=0x60)
        elif entry.name == "HBD":
            entry = dataclasses.replace(entry, size=0x5A000, actual=0x5A000)
        entries.append(entry)
        if entry.name == "HBD":
            entries.append(
                dataclasses.replace(entry, name="HBD_RW", base=0x8B000, size=0x6000, actual=0x6000)
            )
    return renumber(entries)


def renumber(entries: list[cp.TocEntry]) -> list[cp.TocEntry]:
    """Give entries consecutive ids, as fpart does."""
    return [dataclasses.replace(entry, entry_id=index + 1) for index, entry in enumerate(entries)]


def as_backup(entries: list[cp.TocEntry]) -> list[cp.TocEntry]:
    """Turn primary side-A entries into the backup TOC's entries."""
    pointers = {"part": cp.BACKUP_TOC, "BACKUP_PART": 0x0, "OTHER_SIDE": cp.OTHER_SIDE_BACKUP_TOC}
    return [
        dataclasses.replace(entry, base=pointers[entry.name]) if entry.name in pointers else entry
        for entry in entries
    ]


def replace_entry(entries: list[cp.TocEntry], name: str, **changes: int) -> list[cp.TocEntry]:
    """Return ``entries`` with the fields of entry ``name`` changed."""
    found = False
    out: list[cp.TocEntry] = []
    for entry in entries:
        if entry.name == name:
            found = True
            entry = dataclasses.replace(entry, **changes)
        out.append(entry)
    if not found:
        raise KeyError(name)
    return out


def ecc_content(length: int, seed: int) -> bytes:
    """Return ``length`` deterministic data bytes ECC-encoded (9 per 8)."""
    data = hashlib.shake_256(seed.to_bytes(4, "big")).digest(length)
    return cp.ecc_encode(data)


def elf64_le(e_shoff: int, shnum: int = 4, shentsize: int = 64) -> bytes:
    """Return a minimal little-endian ELF64 header."""
    header = bytearray(64)
    header[0:4] = cp.ELF_MAGIC
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 0x10, 2, 0x15, 1)
    struct.pack_into("<Q", header, 0x28, e_shoff)
    struct.pack_into("<HHHHHH", header, 0x34, 64, 56, 1, shentsize, shnum, 1)
    return bytes(header)


def xz_payload(check: int = lzma.CHECK_CRC32, filters: list[dict[str, int]] | None = None) -> bytes:
    """Return an xz stream like ``xz --check=crc32`` makes of a skiboot lid."""
    data = b"OPAL skiboot synthetic payload " * 4096
    if filters is None:
        return lzma.compress(data, format=lzma.FORMAT_XZ, check=check)
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=check, filters=filters)


@dataclasses.dataclass
class Synth:
    """Knobs for one synthetic image; defaults give a passing image."""

    primary: list[cp.TocEntry]
    backup: list[cp.TocEntry]
    payload: bytes
    bootkernel_header: bytes
    version: bytes = SYNTHETIC_VERSION
    erase: tuple[str, ...] = ()


def default_synth() -> Synth:
    """Return the knobs for an image that passes every check."""
    primary = decided_side_a_entries()
    return Synth(
        primary=primary,
        backup=as_backup(primary),
        payload=xz_payload(),
        bootkernel_header=elf64_le(0x1000),
    )


def bootkernel_blob(header: bytes) -> bytes:
    """Return the synthetic zImage.epapr written to BOOTKERNEL."""
    return header + b"\x00" * (0x1000 - len(header)) + b"\x5a" * 0x100


def build_image(synth: Synth) -> bytearray:
    """Render a 64 MiB image from ``synth``."""
    image = bytearray(b"\xff" * cp.IMAGE_SIZE)
    image[cp.PRIMARY_TOC : cp.PRIMARY_TOC + cp.TOC_BLOCK_BYTES] = serialise_toc(synth.primary)
    image[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES] = serialise_toc(synth.backup)
    side_b = (FIXTURES / cp.FIXTURE_LIVE_B).read_bytes()
    image[cp.OTHER_SIDE_TOC : cp.OTHER_SIDE_TOC + cp.TOC_BLOCK_BYTES] = side_b
    for seed, entry in enumerate(synth.primary):
        if entry.name not in cp.CODE_PARTITIONS or entry.name in synth.erase:
            continue
        if entry.name == "PAYLOAD":
            blob = synth.payload
        elif entry.name == "BOOTKERNEL":
            blob = bootkernel_blob(synth.bootkernel_header)
        elif entry.name == "VERSION":
            blob = synth.version.ljust(entry.size, b"\x00")
        elif entry.ecc:
            blob = ecc_content(64 * 8, seed)
        else:
            blob = bytes(range(256))
        image[entry.base : entry.base + len(blob)] = blob
    return image


def run(image: bytes, fixtures: Path = FIXTURES) -> cp.Report:
    """Run the full check and return its report."""
    report, _toc = cp.run_check(bytes(image), fixtures)
    return report


class ViolationCase(unittest.TestCase):
    """Base class providing the violation assertion; it holds no tests."""

    def assertViolation(self, image: bytes, needle: str) -> None:
        """Assert that the check fails with a violation containing ``needle``."""
        report = run(image)
        self.assertTrue(
            any(needle in violation for violation in report.violations),
            f"no violation containing {needle!r}:\n{report.render()}",
        )


class CheckPassesTest(unittest.TestCase):
    """The synthetic image of the decided layout must pass cleanly."""

    def test_decided_layout_passes(self) -> None:
        """The decided side-A layout raises no violation."""
        report = run(build_image(default_synth()))
        self.assertEqual(report.violations, [], report.render())
        text = report.render()
        self.assertRegex(text, r"HBD_RW\s+-\s+0x008b000/0x0006000 .* added")
        self.assertRegex(text, r"TEST\s+0x1dd9000/0x0009000\s+0x1dd9000/0x0009000 .* untouched")
        self.assertRegex(text, r"GUARD\s+.* data, preserved")
        self.assertIn("RESULT: PASS", text)

    def test_live_layout_is_rejected(self) -> None:
        """compute-2's own live TOC fails: no HBD_RW and the old HBD."""
        live = cp.parse_toc((FIXTURES / cp.FIXTURE_LIVE_A).read_bytes(), 0)
        synth = default_synth()
        synth.primary = list(live.entries)
        synth.backup = as_backup(synth.primary)
        report = run(build_image(synth))
        joined = "\n".join(report.violations)
        self.assertIn("code partition HBD_RW is missing", joined)
        self.assertIn("HBD must be exactly 0x0031000/0x005a000", joined)


class TocStructureTest(ViolationCase):
    """Checksums, pointers and geometry of the TOCs."""

    def test_bad_header_checksum(self) -> None:
        """A flipped reserved header byte breaks the header checksum."""
        image = build_image(default_synth())
        image[cp.PRIMARY_TOC + 30] ^= 0x01
        self.assertViolation(image, "header checksum mismatch")

    def test_bad_entry_checksum(self) -> None:
        """A flipped reserved entry byte in the backup TOC breaks its checksum."""
        image = build_image(default_synth())
        image[cp.BACKUP_TOC + cp.FFS_HEADER_BYTES + 3 * cp.FFS_ENTRY_BYTES + 50] ^= 0x10
        self.assertViolation(image, "entry checksum mismatch")

    def test_bad_magic(self) -> None:
        """A primary TOC without the 'PART' magic is unusable."""
        image = build_image(default_synth())
        image[cp.PRIMARY_TOC] = 0x00
        self.assertViolation(image, "is not 'PART'")

    def test_wrong_image_size(self) -> None:
        """Only a 64 MiB image is accepted."""
        image = build_image(default_synth())[: cp.SIDE_SIZE]
        self.assertViolation(image, "expected 0x4000000")

    def test_other_side_pointer(self) -> None:
        """OTHER_SIDE must point at 0x2000000."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "OTHER_SIDE", base=0x2008000)
        self.assertViolation(build_image(synth), "OTHER_SIDE points at 0x2008000")

    def test_backup_pointer(self) -> None:
        """BACKUP_PART must point at 0x1FF8000."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "BACKUP_PART", base=0x1FF0000)
        self.assertViolation(build_image(synth), "BACKUP_PART points at 0x1ff0000")

    def test_backup_toc_must_mirror_primary(self) -> None:
        """The backup TOC must list the same partitions in the same places."""
        synth = default_synth()
        synth.backup = replace_entry(synth.backup, "OCC", misc_flags=0x40)
        self.assertViolation(build_image(synth), "backup TOC entry OCC")

    def test_toc_spanning_several_blocks(self) -> None:
        """A TOC header claiming more than one 4 KiB block cannot ship as toc0.bin."""
        image = build_image(default_synth())
        image[cp.PRIMARY_TOC : cp.PRIMARY_TOC + cp.TOC_BLOCK_BYTES] = serialise_toc(
            decided_side_a_entries(), size_blocks=2
        )
        self.assertViolation(image, "TOC occupies 2 blocks")

    def test_side_b_checksum(self) -> None:
        """A corrupt side-B TOC entry is reported even though side B is never flashed."""
        image = build_image(default_synth())
        image[cp.OTHER_SIDE_TOC + cp.FFS_HEADER_BYTES + 2 * cp.FFS_ENTRY_BYTES + 48] ^= 0x01
        self.assertViolation(image, "side-B TOC: TOC at 0x2000000 entry 2 (DJVPD): entry checksum")


class DataPartitionTest(ViolationCase):
    """Shared and data partitions must match the live side A exactly."""

    def test_moved_data_partition(self) -> None:
        """Moving GUARD by one block is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "GUARD", base=0x2D000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition GUARD changed")

    def test_resized_data_partition(self) -> None:
        """Shrinking NVRAM is caught, also against the side-B fixtures."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "NVRAM", size=0x80000)
        synth.backup = as_backup(synth.primary)
        image = build_image(synth)
        self.assertViolation(image, "data partition NVRAM changed")
        self.assertViolation(image, "no longer matches the copy side B references")

    def test_data_ecc_flag(self) -> None:
        """Flagging NVRAM as ECC on side A is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "NVRAM", data_integ=cp.FFS_INTEG_ECC)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition NVRAM changed")

    def test_data_misc_flags(self) -> None:
        """Dropping GUARD's preserved flag is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "GUARD", misc_flags=0x10)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition GUARD changed")

    def test_missing_data_partition(self) -> None:
        """A side-A TOC without SECBOOT is caught."""
        synth = default_synth()
        synth.primary = renumber([entry for entry in synth.primary if entry.name != "SECBOOT"])
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition SECBOOT is missing")

    def test_moved_untouched_partition(self) -> None:
        """Moving the untouched TEST partition is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "TEST", base=0x1DDA000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition TEST changed")

    def test_missing_untouched_partition(self) -> None:
        """A side-A TOC without the live TEST partition is caught."""
        synth = default_synth()
        synth.primary = renumber([entry for entry in synth.primary if entry.name != "TEST"])
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "data partition TEST is missing")

    def test_tampered_fixture(self) -> None:
        """A fixture that no longer matches SHA256SUMS stops the check."""
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "fixtures"
            shutil.copytree(FIXTURES, copy)
            target = copy / cp.FIXTURE_LIVE_A
            raw = bytearray(target.read_bytes())
            raw[100] ^= 0x01
            target.write_bytes(bytes(raw))
            report = run(build_image(default_synth()), copy)
        self.assertTrue(any("does not match its digest" in item for item in report.violations))


class CodePartitionTest(ViolationCase):
    """Side-A code partitions must follow the decided layout."""

    def test_bad_payload_offset(self) -> None:
        """PAYLOAD must stay at 0xCA9000."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "PAYLOAD", base=0xCAA000)
        synth.backup = as_backup(synth.primary)
        image = build_image(synth)
        self.assertViolation(image, "PAYLOAD must be exactly 0x0ca9000/0x0100000")
        self.assertViolation(image, "overlap")

    def test_bootkernel_size(self) -> None:
        """BOOTKERNEL must stay 0xF00000 at 0xDA9000."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "BOOTKERNEL", size=0xE00000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "BOOTKERNEL must be exactly 0x0da9000/0x0f00000")

    def test_hbd_rw_offset(self) -> None:
        """HBD_RW must be exactly 0x8B000/0x6000."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBD_RW", base=0x8A000, size=0x7000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "HBD_RW must be exactly 0x008b000/0x0006000")

    def test_hbb_moved(self) -> None:
        """HBB must stay where the SBE SEEPROM points."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBB", base=0x1F50000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "HBB moved to 0x1f50000")

    def test_overlap_into_data(self) -> None:
        """A code partition growing into a data partition is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "OCC", size=0x12A000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "overlaps NVRAM")

    def test_code_overlap(self) -> None:
        """Two code partitions overlapping each other is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBRT", size=0x361000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "code partitions HBRT")

    def test_code_in_side_b(self) -> None:
        """A side-A code partition reaching into side B is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "VERSION", base=0x2010000)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "outside side A's code region")

    def test_unknown_partition(self) -> None:
        """A partition outside the decided set is caught."""
        synth = default_synth()
        extra = dataclasses.replace(synth.primary[-1], name="FOO", base=0x1ED0000, size=0x1000)
        synth.primary = renumber([*synth.primary, extra])
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "unexpected partition FOO")

    def test_code_partition_loses_ecc(self) -> None:
        """A code partition that is no longer flagged ECC is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBRT", data_integ=0)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "code partition HBRT changed flags")

    def test_hbd_rw_without_ecc(self) -> None:
        """HBD_RW must carry the live HBD's flags, ECC included."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBD_RW", data_integ=0)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "code partition HBD_RW changed flags")

    def test_code_partition_vercheck(self) -> None:
        """Dropping HBI's sha512Version flag is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "HBI", ver_check=0)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "code partition HBI changed flags")

    def test_code_partition_readonly(self) -> None:
        """Marking a code partition read-only, unlike the live layout, is caught."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "OCC", misc_flags=0x40)
        synth.backup = as_backup(synth.primary)
        self.assertViolation(build_image(synth), "code partition OCC changed flags")

    def test_erased_code_partition(self) -> None:
        """A code partition that was never written is caught."""
        synth = default_synth()
        synth.erase = ("OCC",)
        self.assertViolation(build_image(synth), "code partition OCC is entirely erased")


class ContentTest(ViolationCase):
    """ECC, xz and ELF content checks."""

    def test_uncorrectable_ecc(self) -> None:
        """Two flipped bits in one ECC group are uncorrectable."""
        image = build_image(default_synth())
        hbi = 0x1B1000
        image[hbi + 18] ^= 0x03
        self.assertViolation(image, "ECC partition HBI: 1 uncorrectable and 0 correctable")

    def test_correctable_ecc(self) -> None:
        """One flipped bit is still a violation in a freshly built image."""
        image = build_image(default_synth())
        image[0x949000 + 40] ^= 0x04
        self.assertViolation(image, "ECC partition HBRT: 0 uncorrectable and 1 correctable")

    def test_ecc_in_data_partition(self) -> None:
        """Bad ECC in a written data partition is caught too."""
        image = build_image(default_synth())
        image[0x2C000 : 0x2C000 + 9] = b"\x00" * 8 + b"\x01"
        self.assertViolation(image, "ECC partition GUARD")

    def test_ecc_partial_group(self) -> None:
        """Data in a partition's trailing partial ECC group is caught."""
        image = build_image(default_synth())
        image[0x2C000 + 0x5000 - 1] = 0x00
        self.assertViolation(image, "cannot hold a whole 9-byte ECC group")

    def test_crc64_payload(self) -> None:
        """An xz PAYLOAD with a CRC64 check is caught."""
        synth = default_synth()
        synth.payload = xz_payload(check=lzma.CHECK_CRC64)
        self.assertViolation(build_image(synth), "PAYLOAD xz check is CRC64")

    def test_bcj_payload(self) -> None:
        """An xz PAYLOAD with a BCJ filter in front of LZMA2 is caught."""
        synth = default_synth()
        synth.payload = xz_payload(
            filters=[{"id": lzma.FILTER_POWERPC}, {"id": lzma.FILTER_LZMA2}]
        )
        self.assertViolation(build_image(synth), "only LZMA2 (0x21) is allowed")

    def test_uncompressed_payload(self) -> None:
        """A PAYLOAD that is not xz at all is caught."""
        synth = default_synth()
        synth.payload = b"\x00" * 4096
        self.assertViolation(build_image(synth), "PAYLOAD: no xz stream header magic")

    def test_truncated_payload(self) -> None:
        """A PAYLOAD whose xz stream is cut short is caught."""
        synth = default_synth()
        synth.payload = xz_payload()[:-20]
        self.assertViolation(build_image(synth), "PAYLOAD:")

    def test_oversize_elf(self) -> None:
        """A BOOTKERNEL ELF claiming more than the partition is caught."""
        synth = default_synth()
        synth.bootkernel_header = elf64_le(0xF00000)
        self.assertViolation(build_image(synth), "exceeds the 0xf00000-byte partition")

    def test_stripped_elf(self) -> None:
        """A BOOTKERNEL ELF with e_shoff == 0 is caught."""
        synth = default_synth()
        synth.bootkernel_header = elf64_le(0)
        self.assertViolation(build_image(synth), "e_shoff == 0")

    def test_truncated_elf(self) -> None:
        """Section headers that read as erased flash are caught."""
        synth = default_synth()
        synth.bootkernel_header = elf64_le(0x80000)
        self.assertViolation(build_image(synth), "read as erased flash")

    def test_not_elf(self) -> None:
        """A BOOTKERNEL that is not an ELF image is caught."""
        synth = default_synth()
        synth.bootkernel_header = b"\x00" * 64
        self.assertViolation(build_image(synth), "does not start with an ELF header")

    def test_build_outputs_identical(self) -> None:
        """PAYLOAD and BOOTKERNEL carrying the build outputs byte for byte pass."""
        synth = default_synth()
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "skiboot.lid.xz"
            payload.write_bytes(synth.payload)
            bootkernel = Path(tmp) / "zImage.epapr"
            bootkernel.write_bytes(bootkernel_blob(synth.bootkernel_header))
            report, _toc = cp.run_check(bytes(build_image(synth)), FIXTURES, payload, bootkernel)
        self.assertEqual(report.violations, [], report.render())
        self.assertIn("PAYLOAD carries skiboot.lid.xz byte for byte", report.render())
        self.assertIn("BOOTKERNEL carries zImage.epapr byte for byte", report.render())

    def test_build_output_mismatch(self) -> None:
        """A PAYLOAD that is not the build's skiboot.lid.xz is caught."""
        synth = default_synth()
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "skiboot.lid.xz"
            payload.write_bytes(xz_payload(check=lzma.CHECK_CRC32) + b"extra")
            report, _toc = cp.run_check(bytes(build_image(synth)), FIXTURES, payload=payload)
        self.assertIn("PAYLOAD: partition content differs from build output skiboot.lid.xz", report.violations)

    def test_build_output_too_large(self) -> None:
        """A build output larger than its partition is caught."""
        synth = default_synth()
        with tempfile.TemporaryDirectory() as tmp:
            bootkernel = Path(tmp) / "zImage.epapr"
            bootkernel.write_bytes(b"\x00" * (0xF00000 + 1))
            report, _toc = cp.run_check(bytes(build_image(synth)), FIXTURES, bootkernel=bootkernel)
        self.assertTrue(any("larger than the 0xf00000-byte partition" in item for item in report.violations))


class VersionTest(ViolationCase):
    """The VERSION partition text."""

    def test_version_reported(self) -> None:
        """The first VERSION line appears in the report."""
        report = run(build_image(default_synth()))
        self.assertIn("VERSION: open-power-firestone-v2.7-123-g0123456789", report.render())

    def test_unknown_version(self) -> None:
        """A VERSION built without git metadata is caught."""
        synth = default_synth()
        synth.version = SYNTHETIC_VERSION.replace(b"buildroot-2025.02.18-1-ga872efdc", b"buildroot-unknown")
        self.assertViolation(build_image(synth), "contains 'unknown'")

    def test_dirty_version(self) -> None:
        """A VERSION built from a modified tree is caught."""
        synth = default_synth()
        synth.version = SYNTHETIC_VERSION.replace(b"g0123456789\n", b"g0123456789-dirty\n")
        self.assertViolation(build_image(synth), "contains '-dirty'")

    def test_binary_version(self) -> None:
        """A VERSION that is not text is caught."""
        synth = default_synth()
        synth.version = b"open-power-\x01\x02"
        self.assertViolation(build_image(synth), "control characters")

    def test_empty_version(self) -> None:
        """An all-NUL VERSION is caught."""
        synth = default_synth()
        synth.version = b""
        self.assertViolation(build_image(synth), "VERSION is empty")

    def test_garbage_after_version(self) -> None:
        """Anything but NUL padding after the text is caught."""
        image = build_image(default_synth())
        image[0x1FF7000 + 0xFFF] = 0xFF
        self.assertViolation(image, "non-NUL bytes after")


class EccPortTest(unittest.TestCase):
    """The ECC port against skiboot's libflash/test/test-ecc.c."""

    SKIBOOT_VECTORS = """
    6dd4b78a7c7cd829:b9 4116389840176490:3b 5421d2c72f7dfd77:e4 68614ab639ba026b:bf
    4405ef3e639cfa68:2a 552ef9b358b214e8:35 6ddbb48d65bde2c3:da 6a8709627b48dde1:45
    331483916b9e9f30:e4 1064d6f4397db7d8:6c 6a9e0af33c29ba83:c9 1aec97af79efea3a:09
    438c77e431f40ea9:91 00da6f6b1ebf4ba7:c5 307ca5ef72a8b567:b9 67ff05361e515d79:03
    6f258d9129153dce:36 5e68c20a43476058:ab 58933b4646ca0cc0:42 7d0162c31c992a84:b2
    2a67072852305c76:26 754b3f6c1842bbb5:2b 37ee3f395fd248ce:90 138b99966b02c2cb:40
    4b70e7ff23f0708b:23 24807aa3360ef2f2:19 601a2b0e3f6d1252:a0 2ffedd2d23a6a2f2:c4
    716120fb30d94c98:a5 4265ee9921ddc6ea:ea 238201ff2a64f3d0:3b 402f246312a78f90:0a
    537a319e1e97e66d:a6 55eeefe82c0d6ce4:a4 6561f32d52f052ab:06 48a697690fc8fa55:9a
    2520af213df1d6d5:ed 280bb60b5d0eee5b:66 1dc41fa43b974fa1:a8 4811b126693507a3:5a
    5f87c02c6c922bc9:7e 1f43fa953fa1eb3a:92 2bff3e1b4f42d7c2:e6 63488e2c1d605f16:2b
    001c245a25ae7cc6:78 3f3e2600239e265a:07 501370967f6d4a63:e9 3645b5ea238da234:d2
    1e0530d10c34a5d3:48 4f9b0f19036723fe:7e 5f24f87e1841a682:20 13301e540445a7a0:c7
    56337d573b3bd45f:85 615495fb73f79cfb:06 76d3240029664721:80 5d2ca49e565ae42d:22
    15f872ea7c709f34:f3 15fccf6741f7b105:e9 4bb376f679455d94:63 5f58101b4bcf9b51:47
    1ef3da5a1e96361b:25 6f6dc1ab6f074af0:20 1e03807e25b37795:ef 1294ed243c08b14f:97
    31e81d68622ffc3d:1f 3f6fd54e110d15e7:10 7a71a2bf529ff3a2:40 1552bd8750a52017:b3
    0ddbc80176a75382:45 449cbd1204aeec01:5f 200d9aa321c961b1:51 5b09d02e36060d8d:94
    1e3a00e571069f96:9b 77fdbe9269ed77db:63 6a4bfd2a5755cead:3e 35bd132c093fd784:50
    75ec04c8252ad4d7:05 7847227413ef8546:72 4ade4c6d0adc0f98:9d 4ff836967cc669d5:81
    6d0c0bd60f680be4:2c 0dd37fbc677dae95:72 6207ff8623263d43:f4 3822ceac6fe3c787:5a
    19cd90c57cbf8bbf:e0 7492b38839db2b68:4f 1e88ed704f9c83b7:6b 6fe138f53cc2ee55:72
    40a3234d67def787:b4 26b066302aef2077:7c 3f34c6345c6d795d:5e 342ef7fb3520cafc:c6
    01984e342c761a6f:87 491050434c769aa1:35 37522a07190886d9:6a 493d0477245e35dd:2d
    287092bd57108433:aa 0bdbe4730a789243:fa 7a36c17743feb31f:47 7a5c59ca1404523c:58
    40be3ede6eef0d52:ac 4ddf7da55f472c4e:5c 3e8b91093dc0b69a:95 1c0a1aa37f2eb456:5d
    259fae2242ba80d4:87 2a1dd4cd64d47456:c7 1f27fa315e4cccc8:6e 19f53f5320c04865:00
    0ac2e73763058f96:0e 6d36e3074215113f:be 7c0e166f3673e77e:53 6673471c247ea92c:1c
    0d846bb1724f2b8f:88 2ef73b6f07bb2d28:d0 364ddeaf29539539:c7 1bbf7f65770c1d8d:22
    1842a28b699efd0a:1a 565349dc56ce3395:2a 275fb3a4725d647f:80 55fce7eb4cff61c6:e2
    3517e553001abcb9:ff 31d3d61d543fdf84:54 5e6789814bc91570:02 750027ea692a70b9:1f
    2ecea50662370af1:6f 2b3f81f82adcbb75:b1 18aaf26f11b2c914:7a 4f5b64a1262f5e20:2b
    0401f4a47e52a010:f6 2dea8b493a4fd353:93 27a6354949aa0aae:bf 315bf0e03fe8d7d4:58
    334907b807af3abc:74 16b70b695aa8bb5c:bf 7a0c9f3c6cb3f355:3a 27a81d232f24848f:50
    6cceb00e597bf340:9c 036464144b36398f:0b 254508b078648bfe:21 3460aa485413adb6:1c
    5a9b96ef5fa02c40:90 7ef0692b7346895e:aa 7152f5554e4bcdcc:e8 1975e77e7554e9f9:f8
    4c9e6ddc476072c7:67 2fa4bd4c7444a325:77 110a7d756100ae2c:ca 342d7af94453852d:9b
    68afe8e94ae48663:6c 1efc408a62bc8825:4c 379879b846a45dad:31 11e10cb4246729c6:de
    202050ed154570c8:72 6f9d63554565599d:16 0da9fcc623fe0d9e:37 19790753684593b5:ee
    039e39de1869707e:e7 5b8c1d1374f12f33:34 66b53e4a75020492:2f 6a46192c3353ac26:0c
    3c62775919ead678:6f 27984f4b4d6cf4cf:20 7aeb84a55bc5ca44:5f 11c079fc639b6d8e:c8
    26aa50a730bcba86:20 4657f5b35e42ca5f:12 7761183358390267:af 02a9f42517816920:87
    6d7e73307247577b:d9 5ce6c2bd7b286ff6:fa 16456519765fca10:52 636e03ac19e39ef7:58
    0ec93a8e3efa20bf:82 0ed4ce2b757e78d8:54 33fc2551791ae757:fe 28d224fe705e9cab:fc
    1305bdd0506a7449:9d 3dcb917a0df14275:b9 2c303e8e4f8c0b76:82 718cb00352da8f35:23
    0048c5fd37e4a5b6:b6 311d599577a9de30:7c 101da81d33c74dba:11 0f2b47517d9c1b4d:37
    260ea5356c120a0e:d6 78c48b443c540a4e:0f 6271d41f5c328ef0:6b 5637a946713b0ead:86
    1b2cafaf650c7771:ae 66b987864f28d501:37 5e275ec80f8bac84:86 3f8771ac712d1c98:4e
    5ff620ce7d530326:b5 7f1e5f0d0c265f5c:0b 4cdf0e9c70ab0f10:c9 5f00ee914d27d499:83
    288fb4c6101e4826:16 44d1b2ca38ad5ce4:9c 43e595e153fcfa1b:8e 3649783169f43b16:dc
    400f04292f0e0375:48 264845652280d848:2a 0b4092657c7feeab:2b 13bbe6f6266d4215:89
    618c661c7a756e7c:6d 759617163fb3c4e4:74 0a011b00351d88c2:d4 30e0e17d69f73bce:65
    32708be82fff408a:19 761d9b2a7f4f9a84:58 20aa4f9b551e89bc:4c 4c776f1e493a0461:28
    653cd1e2114921e8:9e 01e76145292267c3:3d 65461c033830d977:55 1316a2da2555202c:85
    673edcec395ee83f:20 47d5f875727f6f52:a4 35ded6ea5b91df6b:ac 18ecb167176b3d06:78
    56074de70e82c87d:31 571f01ea600868e7:3f 43a0513f07ffe367:d6 49ffa4b67610dd27:10
    37ff23f2401d3fe0:ec 756077ab58a9738d:6f 153bc99c41d7e6c9:8f 21e377ee7a789b7f:b7
    532108b123cad934:a9 239b0342386724b4:e2 5bfbb2ab36b1a61c:e1 5dbc44e1433a8f97:64
    70108e5b25923d56:14 35b9fee925ef6545:2d 01241cc14ea6b050:3c 3d5aa24b572b6aa8:8b
    5d2978cd1479a436:f1 3733d38f20c9ca0c:e4 1c79879d01337845:c4 16daa7335478ab8f:0c
    4150b8260c3b1edf:94 2d221f1c568c81c2:9a 4e1305a84f05970b:ec 51051d4121340e5a:57
    72d0703f74a02084:a8 599b330e4ecc22ea:15 2b51c6a0375777ef:e7 1206b2811b6254fc:9a
    5ce9b54547c0b16b:1e 4151ba415e0dd206:56 166761bb7eac5c8d:43 35393cae7390da89:b1
    132600c36c6d103e:ec 145aa4952f9f8860:69 6da088832b354bc9:53 041833f02ef140a9:7a
"""

    def test_known_answers(self) -> None:
        """eccgenerate matches all 256 'check eccgenerate()' rows of test-ecc.c.

        test-ecc.c stores each row as a host-endian integer and passes it
        through be64toh() on the little-endian hosts it runs on, so the
        words here are those rows byte-swapped: the order the bytes have
        in flash.
        """
        pairs = self.SKIBOOT_VECTORS.split()
        self.assertEqual(len(pairs), 256)
        for pair in pairs:
            data_hex, ecc_hex = pair.split(":")
            with self.subTest(data=data_hex):
                data = bytes.fromhex(data_hex)
                ecc = int(ecc_hex, 16)
                self.assertEqual(cp.ecc_generate(int.from_bytes(data, "big")), ecc)
                self.assertEqual(cp.ecc_encode(data), data + bytes([ecc]))
                scan = cp.ecc_scan(data + bytes([ecc]))
                self.assertEqual((scan.correctable, scan.uncorrectable), (0, 0))

    def test_single_bit_syndromes(self) -> None:
        """Each single data-bit flip of an all-ones word maps to its IBM bit number.

        This is the bitflip half of test-ecc.c: row ``i`` flips IBM bit
        ``63 - i`` and eccverify() must name that bit.
        """
        for bit in range(64):
            with self.subTest(bit=bit):
                word = 0xFFFFFFFFFFFFFFFF ^ (1 << (63 - bit))
                self.assertEqual(cp.SYNDROME_MATRIX[cp.ecc_generate(word) ^ 0x00], bit)
                scan = cp.ecc_scan(word.to_bytes(8, "big") + b"\x00")
                self.assertEqual((scan.correctable, scan.uncorrectable), (1, 0))

    def test_ecc_bit_syndromes(self) -> None:
        """A flipped bit in the ECC byte itself maps to skiboot's E0..E7 codes."""
        for bit in range(8):
            with self.subTest(bit=bit):
                self.assertEqual(cp.SYNDROME_MATRIX[1 << bit], 64 + bit)

    def test_erased_group_is_uncorrectable(self) -> None:
        """Nine 0xFF bytes are never valid ECC, which written_length relies on."""
        self.assertEqual(cp.ecc_generate(0xFFFFFFFFFFFFFFFF), 0x00)
        self.assertEqual(cp.ecc_scan(b"\xff" * 9).uncorrectable, 1)

    def test_written_length(self) -> None:
        """Erased tails are excluded and ECC lengths round to whole groups."""
        data = cp.ecc_encode(b"\xff" * 16) + b"\xff" * 20
        self.assertEqual(cp.written_length(data, True), 18)
        self.assertEqual(cp.written_length(b"ab\xff\xff", False), 2)
        self.assertEqual(cp.written_length(b"\xff" * 9, True), 0)


class KitTest(unittest.TestCase):
    """The side-A kit written from a passing image."""

    def test_kit_contents(self) -> None:
        """The kit holds the TOC blocks and code slices only, with valid sums."""
        image = bytes(build_image(default_synth()))
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "firestone.pnor"
            image_path.write_bytes(image)
            out = Path(tmp) / "kit"
            with contextlib.redirect_stdout(io.StringIO()):
                status = cp.main(["kit", str(image_path), "--fixtures", str(FIXTURES), "--out", str(out)])
            self.assertEqual(status, 0)
            files = sorted(path.name for path in out.iterdir())
            expected = sorted(
                ["toc0.bin", "toc1.bin", "VERSION", "manifest.json", "SHA256SUMS"]
                + [f"{name}.bin" for name in cp.CODE_PARTITIONS]
            )
            self.assertEqual(files, expected)
            self.assertEqual((out / "VERSION").read_bytes(), SYNTHETIC_VERSION)
            for name in cp.DATA_PARTITIONS:
                self.assertFalse((out / f"{name}.bin").exists())
            self.assertEqual((out / "toc0.bin").read_bytes(), image[: cp.TOC_BLOCK_BYTES])
            self.assertEqual(
                (out / "toc1.bin").read_bytes(),
                image[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES],
            )
            manifest = json.loads((out / "manifest.json").read_text(encoding="ascii"))
            self.assertEqual(manifest["version"], SYNTHETIC_VERSION.decode("ascii"))
            self.assertEqual(
                [part["name"] for part in manifest["partitions"]],
                ["HBD", "HBD_RW", "HBI", "SBEC", "SBE", "WINK", "HBRT", "PAYLOAD",
                 "BOOTKERNEL", "OCC", "CAPP", "IMA_CATALOG", "HBB", "VERSION"],
            )
            for part in manifest["partitions"]:
                blob = (out / part["file"]).read_bytes()
                self.assertEqual(len(blob), part["size"])
                self.assertEqual(blob, image[part["base"] : part["base"] + part["size"]])
                self.assertEqual(hashlib.sha256(blob).hexdigest(), part["sha256"])
            self.assertEqual(
                sorted(item["name"] for item in manifest["do_not_write"]),
                sorted((*cp.DATA_PARTITIONS, *cp.UNTOUCHED_LIVE_PARTITIONS)),
            )
            sums = (out / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            self.assertEqual(sorted(line.split("  ")[1] for line in sums), sorted(set(expected) - {"SHA256SUMS"}))
            for line in sums:
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest)

    def test_kit_refused_for_bad_image(self) -> None:
        """No kit is written when any check fails."""
        synth = default_synth()
        synth.primary = replace_entry(synth.primary, "GUARD", base=0x2D000)
        synth.backup = as_backup(synth.primary)
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "firestone.pnor"
            image_path.write_bytes(bytes(build_image(synth)))
            out = Path(tmp) / "kit"
            with contextlib.redirect_stdout(io.StringIO()):
                status = cp.main(["kit", str(image_path), "--fixtures", str(FIXTURES), "--out", str(out)])
            self.assertEqual(status, 1)
            self.assertFalse(out.exists())


class FwFeaturesTest(unittest.TestCase):
    """The fw-features guard against hostboot's static table."""

    def test_master_p8_table_passes(self) -> None:
        """hostboot master-p8 3267aff2bc's table is what compute-2 needs."""
        report = cp.run_fwfeatures(MASTER_P8_INIT_FLAGS)
        self.assertEqual(report.violations, [], report.render())

    def test_count_cache_disabled_off(self) -> None:
        """Turning fw-count-cache-disabled off is caught."""
        source = MASTER_P8_INIT_FLAGS.replace(
            '{"fw-count-cache-disabled",                     0x8000000000000000}',
            '{"fw-count-cache-disabled",                     0x0000000000000000}',
        )
        report = cp.run_fwfeatures(source)
        self.assertIn("fw-count-cache-disabled is disabled, expected enabled", report.violations)

    def test_thread_split_on(self) -> None:
        """Re-enabling fw-l1d-thread-split is caught."""
        source = MASTER_P8_INIT_FLAGS.replace(
            '{"fw-l1d-thread-split",                         0x0000000000000000}',
            '{"fw-l1d-thread-split",                         0x8000000000000000}',
        )
        report = cp.run_fwfeatures(source)
        self.assertIn("fw-l1d-thread-split is enabled, expected disabled", report.violations)

    def test_bcctrl_serialized_on(self) -> None:
        """Enabling fw-bcctrl-serialized is caught."""
        source = MASTER_P8_INIT_FLAGS.replace(
            '{"fw-bcctrl-serialized",                        0x0000000000000000}',
            '{"fw-bcctrl-serialized",                        0x8000000000000000}',
        )
        report = cp.run_fwfeatures(source)
        self.assertIn("fw-bcctrl-serialized is enabled, expected disabled", report.violations)

    def test_missing_entry(self) -> None:
        """A table without fw-count-cache-disabled (pre-c8935157f6) is caught."""
        source = MASTER_P8_INIT_FLAGS.replace(
            '{"fw-count-cache-disabled",                     0x8000000000000000},\n', ""
        )
        report = cp.run_fwfeatures(source)
        self.assertIn("fw-count-cache-disabled is missing from initFlagArray", report.violations)

    def test_unparseable_table(self) -> None:
        """An entry the parser cannot read fails loudly."""
        source = MASTER_P8_INIT_FLAGS.replace(
            '{"tm-suspend-mode",                             0x8000000000000000},',
            '{"tm-suspend-mode",                             INIT_FLAG_ENABLED},',
        )
        report = cp.run_fwfeatures(source)
        self.assertTrue(any("does not understand" in item for item in report.violations))


class FixtureTest(unittest.TestCase):
    """The committed fixtures themselves."""

    def test_fixtures_authentic(self) -> None:
        """All four fixtures load, parse cleanly and match SHA256SUMS."""
        fixtures = cp.load_fixtures(FIXTURES)
        self.assertEqual(len(fixtures.live_a.entries), 28)
        self.assertEqual(len(fixtures.live_b.entries), 23)
        part = fixtures.live_b.find("part")
        self.assertIsNotNone(part)
        if part is not None:
            self.assertTrue(part.misc_flags & 0x01)


LIVE_PNOR = os.environ.get("FIRESTONE_LIVE_PNOR", "")


@unittest.skipUnless(LIVE_PNOR, "FIRESTONE_LIVE_PNOR is not set")
class LiveImageTest(unittest.TestCase):
    """Validate the parser and the ECC port against a private dump of compute-2."""

    image: bytes

    @classmethod
    def setUpClass(cls) -> None:
        """Read the dump once; it is only ever held in memory."""
        cls.image = Path(LIVE_PNOR).read_bytes()

    def test_tocs_match_fixtures(self) -> None:
        """The four committed fixtures are the dump's TOC blocks."""
        for offset, name in (
            (cp.PRIMARY_TOC, cp.FIXTURE_LIVE_A),
            (cp.BACKUP_TOC, cp.FIXTURE_LIVE_A_BACKUP),
            (cp.OTHER_SIDE_TOC, cp.FIXTURE_LIVE_B),
            (cp.OTHER_SIDE_BACKUP_TOC, cp.FIXTURE_LIVE_B_BACKUP),
        ):
            with self.subTest(fixture=name):
                block = self.image[offset : offset + cp.TOC_BLOCK_BYTES]
                self.assertEqual(block, (FIXTURES / name).read_bytes())

    def test_live_ecc_is_clean(self) -> None:
        """Every ECC partition on live side A scans clean over its written bytes."""
        toc = cp.parse_toc(self.image, cp.PRIMARY_TOC)
        for entry in toc.entries:
            if not entry.ecc or entry.name in cp.TOC_ENTRY_NAMES:
                continue
            with self.subTest(partition=entry.name):
                region = self.image[entry.base : entry.end]
                length = cp.written_length(region, True)
                self.assertLessEqual(length, len(region))
                scan = cp.ecc_scan(region[:length])
                self.assertEqual((scan.correctable, scan.uncorrectable), (0, 0))

    def test_live_contents(self) -> None:
        """The live PAYLOAD, BOOTKERNEL and VERSION parse the way the checks expect."""
        toc = cp.parse_toc(self.image, cp.PRIMARY_TOC)
        payload = toc.find("PAYLOAD")
        bootkernel = toc.find("BOOTKERNEL")
        version = toc.find("VERSION")
        if payload is None or bootkernel is None or version is None:
            self.fail("live side-A TOC lacks PAYLOAD, BOOTKERNEL or VERSION")
        stream = cp.parse_xz(self.image[payload.base : payload.end])
        self.assertEqual(stream.check_type, cp.XZ_CHECK_CRC32)
        self.assertEqual(stream.block_filters, ((cp.XZ_FILTER_LZMA2,),))
        elf = cp.elf_size(self.image[bootkernel.base : bootkernel.base + 64])
        self.assertEqual(elf.size, cp.LIVE_BOOTKERNEL_ELF_SIZE)
        self.assertTrue(cp.version_text(self.image[version.base : version.end]))

    def test_live_layout_fails_only_on_the_hbd_split(self) -> None:
        """The live image violates only the HBD/HBD_RW split."""
        report, _toc = cp.run_check(self.image, FIXTURES)
        self.assertTrue(report.violations)
        for violation in report.violations:
            with self.subTest(violation=violation):
                self.assertRegex(violation, r"\b(HBD|HBD_RW)\b")


if __name__ == "__main__":
    unittest.main()

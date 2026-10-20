#!/usr/bin/env python3
"""Unit tests for flash_side_a.py.

No test needs pflash or touches a flash.  Every write goes through a fake
``pflash`` written into a temporary directory: it implements, on an image
file, exactly the subset of skiboot v7.0 pflash the tool relies on (``-v``
and ``-F FILE -f -e -a BASE -s SIZE -p FILE``, erasing to 0xFF and then
programming at most SIZE bytes of FILE), refuses ``-P``, records every
invocation and can be told to corrupt, fail, signal or write a stray byte.

The synthetic tests cut a kit from the image ``test_check_pnor`` synthesises
for the decided layout and build a live backup from the committed live TOC
fixtures, so they run anywhere.  Setting ``FIRESTONE_LIVE_PNOR`` to the
private dump of compute-2's flash and ``FIRESTONE_KIT`` to the side-A kit cut
by CI repeats the flow tests on the real data; the dump is only ever read in
place or copied into temporary directories.
"""

import contextlib
import dataclasses
import errno
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import check_pnor as cp
import flash_side_a as fsa
import test_check_pnor as tcp

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
LIVE_PNOR = os.environ.get("FIRESTONE_LIVE_PNOR", "")
LIVE_KIT = os.environ.get("FIRESTONE_KIT", "")
HOSTBOOT_ORDER = [
    "HBD", "HBD_RW", "HBI", "SBEC", "SBE", "WINK", "HBRT", "PAYLOAD",
    "OCC", "CAPP", "IMA_CATALOG", "VERSION", "HBB",
]
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00 ")

FAKE_PFLASH_BODY = r'''

def main() -> int:
    """Erase and program like pflash.c's erase_range and program_file on a file backend."""
    with open(CALLS, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
    try:
        options, rest = getopt.getopt(sys.argv[1:], "a:s:P:r:43Eep:fdihvbtgS:T:c9F:")
    except getopt.GetoptError as exc:
        print(f"Unrecognised option '{exc.opt}'", file=sys.stderr)
        return 1
    if rest:
        print(f'Unrecognised option or argument "{rest[0]}"', file=sys.stderr)
        return 1
    flags = dict(options)
    if "-v" in flags:
        print("Open-Power Flash tool fake-v7.0")
        return 0
    if "-P" in flags:
        print("this fake pflash implements no partition access", file=sys.stderr)
        return 1
    if "-F" not in flags:
        print("this fake pflash only operates on a flash file", file=sys.stderr)
        return 1
    if "-f" not in flags:
        print('Enter "yes" to confirm:', end="")
        if sys.stdin.readline().strip() != "yes":
            return 1
    address = int(flags.get("-a", "0"), 0)
    program = flags.get("-p")
    if "-s" in flags:
        size = int(flags["-s"], 0)
    elif program is not None:
        size = os.path.getsize(program)
    else:
        size = 0
    with open(flags["-F"], "r+b") as image:
        if "-e" in flags:
            print(f"About to erase 0x{address:08x}..0x{address + size:08x} !")
            print("\r[" + " " * 50 + "] 0%\r[" + "=" * 50 + "] 100%")
            image.seek(address)
            image.write(b"\xff" * size)
        if MODE == "fail":
            print(f"Flash write error 8 for chunk at 0x{address:08x}", file=sys.stderr)
            return 8
        if program is not None:
            with open(program, "rb") as source:
                data = bytearray(source.read()[:size])
            if MODE == "corrupt" or (MODE == "corrupt-once" and not os.path.exists(STATE)):
                open(STATE, "w").close()
                data[len(data) // 2] ^= 0x01
            print(f'About to program "{program}" at 0x{address:08x}..0x{address + size:08x} !')
            image.seek(address)
            image.write(data)
    if MODE.startswith("stray:"):
        with open(flags["-F"], "r+b") as image:
            image.seek(int(MODE.split(":", 1)[1], 0))
            image.write(b"\x00")
    if MODE in SIGNALS and not os.path.exists(STATE):
        open(STATE, "w").close()
        os.kill(os.getppid(), SIGNALS[MODE])
    return 0


sys.exit(main())
'''


@dataclasses.dataclass(frozen=True)
class FakePflash:
    """A fake pflash executable and the record of its invocations."""

    path: Path
    calls_file: Path

    def calls(self) -> list[list[str]]:
        """Return every argument vector the fake was run with."""
        if not self.calls_file.exists():
            return []
        calls: list[list[str]] = []
        for line in self.calls_file.read_text(encoding="utf-8").splitlines():
            value: object = json.loads(line)
            if not isinstance(value, list):
                raise AssertionError(f"bad call record {line!r}")
            calls.append([str(item) for item in value])
        return calls

    def writes(self) -> list[list[str]]:
        """Return the invocations other than ``-v``."""
        return [call for call in self.calls() if call != ["-v"]]


def make_fake_pflash(directory: Path, mode: str = "ok") -> FakePflash:
    """Write a fake pflash into ``directory`` that behaves according to ``mode``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "pflash"
    calls = directory / "pflash-calls.jsonl"
    state = directory / "pflash-state"
    header = (
        f"#!{sys.executable}\n"
        '"""Fake pflash: skiboot v7.0 pflash -v/-F/-f/-e/-a/-s/-p semantics on an image file."""\n'
        "import getopt\nimport json\nimport os\nimport signal\nimport sys\n\n"
        f"MODE = {mode!r}\nCALLS = {str(calls)!r}\nSTATE = {str(state)!r}\n"
        'SIGNALS = {"signal": signal.SIGTERM, "sigquit": signal.SIGQUIT}\n'
    )
    path.write_text(header + FAKE_PFLASH_BODY, encoding="utf-8")
    path.chmod(0o755)
    return FakePflash(path, calls)


def synthetic_backup() -> bytes:
    """Build a 64 MiB live backup from the committed live TOC fixtures.

    Every live side-A partition except TEST carries deterministic content
    (ECC-encoded where the TOC says ECC) and every side-B partition carries
    its own pattern, so that any stray write shows up.
    """
    image = bytearray(b"\xff" * cp.IMAGE_SIZE)
    for offset, name in (
        (cp.PRIMARY_TOC, cp.FIXTURE_LIVE_A),
        (cp.BACKUP_TOC, cp.FIXTURE_LIVE_A_BACKUP),
        (cp.OTHER_SIDE_TOC, cp.FIXTURE_LIVE_B),
        (cp.OTHER_SIDE_BACKUP_TOC, cp.FIXTURE_LIVE_B_BACKUP),
    ):
        image[offset : offset + cp.TOC_BLOCK_BYTES] = (FIXTURES / name).read_bytes()
    live = cp.parse_toc(image, cp.PRIMARY_TOC)
    for seed, entry in enumerate(live.entries):
        if entry.name in cp.TOC_ENTRY_NAMES or entry.name in cp.UNTOUCHED_LIVE_PARTITIONS:
            continue
        if entry.ecc:
            blob = tcp.ecc_content(64 * 8, 1000 + seed)
        else:
            blob = hashlib.shake_256(f"live {entry.name}".encode("ascii")).digest(512)
        image[entry.base : entry.base + len(blob)] = blob
    side_b = cp.parse_toc(image, cp.OTHER_SIDE_TOC)
    for entry in side_b.entries:
        if entry.name in cp.TOC_ENTRY_NAMES or entry.base < cp.SIDE_SIZE:
            continue
        blob = hashlib.shake_256(f"golden {entry.name}".encode("ascii")).digest(4096)
        image[entry.base : entry.base + len(blob)] = blob
    return bytes(image)


def cut_synthetic_kit(out: Path) -> None:
    """Cut a kit with ``check_pnor`` from the synthetic image of the decided layout."""
    image = bytes(tcp.build_image(tcp.default_synth()))
    report, toc = cp.run_check(image, FIXTURES)
    if toc is None or report.violations:
        raise AssertionError(report.render())
    cp.write_kit(image, toc, out)


def as_record(value: object) -> dict[str, object]:
    """Narrow a decoded JSON value to an object."""
    if not isinstance(value, dict):
        raise AssertionError(f"{value!r} is not a JSON object")
    return {str(key): item for key, item in value.items()}


def as_array(value: object) -> list[object]:
    """Narrow a decoded JSON value to an array."""
    if not isinstance(value, list):
        raise AssertionError(f"{value!r} is not a JSON array")
    items: list[object] = list(value)
    return items


def reseal(kit: Path) -> None:
    """Rewrite SHA256SUMS for the current content of every file it lists."""
    sums = fsa.parse_sums((kit / "SHA256SUMS").read_text(encoding="ascii"))
    lines = [f"{hashlib.sha256((kit / name).read_bytes()).hexdigest()}  {name}\n" for name in sums]
    (kit / "SHA256SUMS").write_text("".join(lines), encoding="ascii")


def edit_manifest(kit: Path, change: Callable[[dict[str, object]], None]) -> None:
    """Apply ``change`` to the kit's manifest and reseal the kit."""
    manifest = as_record(json.loads((kit / "manifest.json").read_text(encoding="ascii")))
    change(manifest)
    (kit / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="ascii")
    reseal(kit)


def map_records(manifest: dict[str, object], key: str, change: Callable[[dict[str, object]], None]) -> None:
    """Replace the array ``manifest[key]`` by its records, each passed through ``change``."""
    records = [as_record(item) for item in as_array(manifest[key])]
    for record in records:
        change(record)
    manifest[key] = records


def set_field(
    key: str, match: tuple[str, str], field: str, value: object
) -> Callable[[dict[str, object]], None]:
    """Return a manifest change setting ``field`` of the ``key`` record whose ``match`` pair holds."""

    def change(manifest: dict[str, object]) -> None:
        """Apply the change to the matching record."""

        def update(record: dict[str, object]) -> None:
            """Set the field when the record matches."""
            if record.get(match[0]) == match[1]:
                record[field] = value

        map_records(manifest, key, update)

    return change


class FullDisk(io.StringIO):
    """A log stream that fails every write the way a full file system does."""

    def write(self, text: str, /) -> int:
        """Refuse the write with ENOSPC."""
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))


def refuse_sleep(seconds: float) -> None:
    """Stand in for ``time.sleep`` where no retry may happen; no test ever really sleeps."""
    raise AssertionError(f"unexpected retry delay of {seconds} s")


def run_main(argv: list[str], sleep: Callable[[float], None] = refuse_sleep) -> tuple[int, str]:
    """Run the tool's ``main`` with ``sleep`` as the retry sleeper and return its status and output."""
    out = io.StringIO()
    status = fsa.main(argv, out=out, sleep=sleep)
    return status, out.getvalue()


def reset_held_signals(test: unittest.TestCase) -> None:
    """Give the held signals Python's foreground dispositions for one test and restore them afterwards.

    A shell starts a background job with SIGINT and SIGQUIT ignored, and
    ``DeferredSignals`` leaves an ignored signal alone, so without this the
    signal tests would depend on how the suite was launched.
    """
    for signum in fsa.DeferredSignals.SIGNALS:
        previous = signal.getsignal(signum)
        if previous is None:
            raise AssertionError(f"{signal.Signals(signum).name} has a handler not installed from Python")
        test.addCleanup(signal.signal, signum, previous)
        signal.signal(signum, signal.default_int_handler if signum == signal.SIGINT else signal.SIG_DFL)


class FenceTest(unittest.TestCase):
    """The write fence and the hard-coded layout it rests on."""

    def setUp(self) -> None:
        """Use a fence with nothing but the hard-coded protected partitions."""
        self.fence = fsa.WriteFence()

    def test_hard_coded_layout_is_compute2s(self) -> None:
        """The hard-coded tables match the committed live TOC of compute-2."""
        live = cp.parse_toc((FIXTURES / cp.FIXTURE_LIVE_A).read_bytes(), 0)
        self.assertEqual(set(fsa.LIVE_PROTECTED), {*cp.DATA_PARTITIONS, *cp.UNTOUCHED_LIVE_PARTITIONS})
        self.assertEqual(set(fsa.NEW_CODE), set(cp.CODE_PARTITIONS))
        for name, (base, size) in [*fsa.LIVE_PROTECTED.items(), *fsa.LIVE_CODE.items()]:
            entry = live.find(name)
            self.assertIsNotNone(entry, name)
            if entry is not None:
                self.assertEqual((entry.base, entry.size), (base, size), name)
        self.assertEqual(fsa.NEW_CODE["HBD"], (0x31000, 0x5A000))
        self.assertEqual(fsa.NEW_CODE["HBD_RW"], (0x8B000, 0x6000))

    def test_side_b_refused(self) -> None:
        """Any byte at or above 0x2000000 is refused."""
        for base, size in ((0x2000000, 0x1000), (0x1FFF000, 0x2000), (0x3FF8000, 0x1000)):
            with self.subTest(base=hex(base)):
                problems = self.fence.problems("x", base, size)
                self.assertTrue(any("side B is never written" in problem for problem in problems), problems)

    def test_every_protected_partition_refused(self) -> None:
        """Every shared or untouched partition, and any range overlapping one, is refused."""
        for name, (base, size) in fsa.LIVE_PROTECTED.items():
            for start, length in ((base, size), (base - 0x1000, 0x2000), (base + size - 0x1000, 0x2000)):
                with self.subTest(partition=name, start=hex(start)):
                    problems = self.fence.problems("x", start, length)
                    self.assertTrue(any(f"protected partition {name} " in problem for problem in problems))

    def test_guard_overlap_refused(self) -> None:
        """A write into GUARD is refused by name."""
        with self.assertRaisesRegex(fsa.FenceError, "overlaps protected partition GUARD"):
            self.fence.check("HBD", 0x2C000, 0x5A000)

    def test_toc_blocks_only_exactly(self) -> None:
        """The two TOC blocks are allowed, but nothing else in the TOC partitions."""
        self.assertEqual(self.fence.problems("toc0", 0x0, 0x1000), [])
        self.assertEqual(self.fence.problems("toc1", 0x1FF8000, 0x1000), [])
        for base, size in ((0x0, 0x2000), (0x1000, 0x1000), (0x1FF9000, 0x1000), (0x1FF8000, 0x8000)):
            with self.subTest(base=hex(base), size=hex(size)):
                self.assertNotEqual(self.fence.problems("x", base, size), [])

    def test_misaligned_refused(self) -> None:
        """Ranges not aligned to the 4 KiB erase block are refused."""
        self.assertNotEqual(self.fence.problems("x", 0x31800, 0x1000), [])
        self.assertNotEqual(self.fence.problems("x", 0x31000, 0x1800), [])
        self.assertNotEqual(self.fence.problems("x", 0x31000, 0), [])

    def test_code_ranges_allowed(self) -> None:
        """Every live and new code partition may be written."""
        for name, (base, size) in [*fsa.LIVE_CODE.items(), *fsa.NEW_CODE.items()]:
            with self.subTest(partition=name):
                self.assertEqual(self.fence.problems(name, base, size), [])

    def test_extra_regions_only_widen(self) -> None:
        """Regions handed to the fence add protection and never remove the hard-coded set."""
        fence = fsa.WriteFence([fsa.Region("EXTRA", 0x1B1000, 0x1000)])
        self.assertNotEqual(fence.problems("HBI", 0x1B1000, 0x5A0000), [])
        self.assertNotEqual(fence.problems("x", 0x2C000, 0x1000), [])

    def test_flasher_refuses_without_any_manifest(self) -> None:
        """The flasher itself refuses side-B and GUARD writes before running pflash."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "image.bin"
            image.write_bytes(b"\xff" * cp.IMAGE_SIZE)
            pflash = make_fake_pflash(root / "bin")
            device = fsa.open_image(image, None)
            with fsa.ActionLog(root / "log", io.StringIO()) as log, fsa.DeferredSignals() as signals:
                erased = b"\xff" * cp.IMAGE_SIZE
                flasher = fsa.Flasher(
                    device, pflash.path, fsa.WriteFence(), log, root, signals, erased, fsa._no_host_guard,
                    refuse_sleep,
                )
                for item in (
                    fsa.WriteItem("evil", cp.SIDE_SIZE, b"\x00" * 0x1000),
                    fsa.WriteItem("evil", 0x2C000, b"\x00" * 0x1000),
                ):
                    with self.subTest(base=hex(item.base)), self.assertRaises(fsa.Refused):
                        flasher.apply([fsa.WriteItem("HBD", 0x31000, b"\x00" * 0x1000), item])
            self.assertEqual(pflash.calls(), [])
            self.assertEqual(image.read_bytes(), b"\xff" * cp.IMAGE_SIZE)

    def test_pflash_command(self) -> None:
        """Each write is one erase-and-program of an exact range, never by partition."""
        command = fsa.pflash_command(Path("/usr/sbin/pflash"), Path("/dev/mtd6"), 0x31000, 0x5A000, Path("H"))
        expected = ["/usr/sbin/pflash", "-F", "/dev/mtd6", "-f", "-e"]
        expected += ["-a", "0x31000", "-s", "0x5a000", "-p", "H"]
        self.assertEqual(command, expected)

    def test_changes_outside(self) -> None:
        """Changes inside items are ignored, in runtime-written partitions noted and elsewhere fatal."""
        before = bytes(cp.IMAGE_SIZE)
        after = bytearray(before)
        item = fsa.WriteItem("HBI", 0x1B1000, b"\x01" * 0x2000)
        after[item.base : item.end] = item.data
        after[fsa.LIVE_PROTECTED["GUARD"][0] + 7] = 1
        after[0x1ECF000] = 1
        after[0x1ED0FFF] = 1
        outcome = fsa.changes_outside(before, bytes(after), [item])
        self.assertEqual(len(outcome.fatal), 1, outcome.fatal)
        self.assertIn("0x1ecf000..0x1ed1000 changed during this run although it was not written", outcome.fatal[0])
        self.assertEqual(len(outcome.notes), 1, outcome.notes)
        self.assertIn("GUARD", outcome.notes[0])
        self.assertEqual(fsa.changes_outside(before, before, [item]), fsa.Preservation((), ()))

    def test_firmware_maintained_drift_is_noted_but_a_change_during_a_run_is_fatal(self) -> None:
        """VPD cache drift is a note, TEST, BMC_INV and SECBOOT drift is fatal; a change during a run is fatal."""
        self.assertEqual(fsa.FIRMWARE_MAINTAINED, frozenset({"DJVPD", "MVPD", "CVPD"}))
        self.assertEqual(fsa.RUNTIME_WRITTEN & fsa.FIRMWARE_MAINTAINED, frozenset())
        unwritten = frozenset(fsa.LIVE_PROTECTED) - fsa.RUNTIME_WRITTEN - fsa.FIRMWARE_MAINTAINED
        self.assertEqual(unwritten, frozenset({"TEST", "BMC_INV", "SECBOOT"}))
        backup = bytes(cp.IMAGE_SIZE)
        for name in sorted(unwritten):
            with self.subTest(partition=name):
                drifted = bytearray(backup)
                drifted[fsa.LIVE_PROTECTED[name][0] + 0x20] = 1
                preserved = fsa.compare_preserved(bytes(drifted), backup)
                self.assertEqual(preserved.notes, ())
                self.assertEqual(len(preserved.fatal), 1, preserved.fatal)
                self.assertTrue(preserved.fatal[0].startswith(f"{name} "), preserved.fatal)
        image = bytearray(backup)
        for name in sorted(fsa.FIRMWARE_MAINTAINED):
            image[fsa.LIVE_PROTECTED[name][0] + 0x20] = 1
        preserved = fsa.compare_preserved(bytes(image), backup)
        self.assertEqual(preserved.fatal, ())
        self.assertEqual(len(preserved.notes), len(fsa.FIRMWARE_MAINTAINED), preserved.notes)
        for note in preserved.notes:
            self.assertIn(
                "(hostboot rewrites this VPD cache at IPL; the backup's copy is stale and no stage ever "
                "writes or restores it)",
                note,
            )
        image[cp.SIDE_SIZE + 0x800000] = 1
        self.assertEqual(len(fsa.compare_preserved(bytes(image), backup).fatal), 1)
        during = fsa.changes_outside(backup, bytes(image[: cp.SIDE_SIZE]) + backup[cp.SIDE_SIZE :], [])
        self.assertEqual(during.notes, ())
        self.assertEqual(len(during.fatal), len(fsa.FIRMWARE_MAINTAINED), during.fatal)
        mvpd = fsa.LIVE_PROTECTED["MVPD"][0]
        self.assertIn(
            f"{fsa._span(mvpd, cp.BLOCK_SIZE)} changed during this run although it was not written",
            "\n".join(during.fatal),
        )

    def test_stage_items(self) -> None:
        """Rollback ranges are the live layout; hostboot runs in address order with HBB last."""
        backup = fsa.Backup(Path("b"), bytes(cp.IMAGE_SIZE), "", cp.parse_toc(
            (FIXTURES / cp.FIXTURE_LIVE_A).read_bytes(), 0), cp.parse_toc(
            (FIXTURES / cp.FIXTURE_LIVE_A_BACKUP).read_bytes(), 0), ())
        hostboot = fsa.rollback_items(backup, fsa.Stage.HOSTBOOT)
        live_order = [name for name in HOSTBOOT_ORDER if name != "HBD_RW"]
        self.assertEqual([item.name for item in hostboot], live_order)
        self.assertEqual((hostboot[0].base, hostboot[0].size), (0x31000, 0x60000))
        self.assertEqual(
            [(item.base, item.size) for item in fsa.rollback_items(backup, fsa.Stage.TOC)],
            [(0x0, 0x1000), (0x1FF8000, 0x1000)],
        )
        self.assertEqual(
            [(item.base, item.end) for item in fsa.rollback_items(backup, fsa.Stage.BOOTKERNEL)],
            [(0xDA9000, 0x1CA9000)],
        )


class HostTest(unittest.TestCase):
    """MTD resolution by name and the opal-prd guard."""

    def make_sysfs(self, root: Path, devices: dict[str, dict[str, str | bytes]]) -> Path:
        """Create a fake /sys/class/mtd tree; text attributes get a newline, binary ones are written raw."""
        sysfs = root / "sys"
        for name, attributes in devices.items():
            (sysfs / name).mkdir(parents=True)
            for attribute, value in attributes.items():
                path = sysfs / name / attribute
                path.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(value, bytes):
                    path.write_bytes(value)
                else:
                    path.write_text(value + "\n", encoding="ascii")
        return sysfs

    def flash_attributes(self, size: int = cp.IMAGE_SIZE) -> dict[str, str | bytes]:
        """Return the sysfs attributes of the OPAL flash@0 MTD."""
        return {
            "name": "flash@0",
            "size": str(size),
            "erasesize": "4096",
            "flags": "0xc00",
            "dev": "90:12",
            "type": "nor",
            "device/of_node/compatible": b"ibm,opal-flash\0",
        }

    def test_resolves_by_name(self) -> None:
        """The flash@0 MTD is found whatever its index, past a Solarflare NIC's MTDs."""
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = self.make_sysfs(
                Path(tmp),
                {
                    "mtd0": {"name": "enP1p1s0f0 sfc_mcfw:00", "size": "1048576", "erasesize": "65536",
                             "dev": "90:0", "type": "nor"},
                    "mtd0ro": {"name": "enP1p1s0f0 sfc_mcfw:00", "dev": "90:1"},
                    "mtd6": self.flash_attributes(),
                    "mtd6ro": {"name": "flash@0", "dev": "90:13"},
                },
            )
            info = fsa.find_flash_mtd(sysfs)
            self.assertEqual((info.index, info.dev, info.ro_dev, info.flags), (6, (90, 12), (90, 13), 0xC00))
            self.assertEqual((info.name, info.offset), ("flash@0", None))

    def test_refuses_ambiguous_missing_or_wrong_geometry(self) -> None:
        """Two flash@0 MTDs, none, or a wrong size are refused."""
        cases: dict[str, dict[str, dict[str, str | bytes]]] = {
            "two": {
                "mtd6": self.flash_attributes(),
                "mtd6ro": {"dev": "90:13"},
                "mtd12": self.flash_attributes(),
                "mtd12ro": {"dev": "90:25"},
            },
            "none": {"mtd0": {"name": "bmc", "size": "1048576"}},
            "size": {"mtd6": self.flash_attributes(0x2000000), "mtd6ro": {"dev": "90:13"}},
        }
        for label, devices in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(fsa.DeviceError):
                    fsa.find_flash_mtd(self.make_sysfs(Path(tmp), devices))

    def test_refuses_flash_at_0_that_is_not_the_opal_flash(self) -> None:
        """An MTD called flash@0 that is not NOR or whose node is not ibm,opal-flash is refused."""
        nic: dict[str, str | bytes] = {**self.flash_attributes(), "device/of_node/compatible": b"pciex1924,a03\0"}
        nand: dict[str, str | bytes] = {**self.flash_attributes(), "type": "nand"}
        orphan = self.flash_attributes()
        del orphan["device/of_node/compatible"]
        cases: dict[str, tuple[dict[str, str | bytes], str]] = {
            "nic": (nic, "compatible with \\[pciex1924,a03\\], not ibm,opal-flash"),
            "nand": (nand, "of type 'nand', not 'nor'"),
            "no node": (orphan, "cannot read .*of_node/compatible"),
        }
        for label, (attributes, message) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                sysfs = self.make_sysfs(Path(tmp), {"mtd6": attributes, "mtd6ro": {"dev": "90:13"}})
                with self.assertRaisesRegex(fsa.DeviceError, message):
                    fsa.find_flash_mtd(sysfs)

    def test_opal_flash_node_with_several_compatibles(self) -> None:
        """ibm,opal-flash anywhere in the NUL-separated compatible list is accepted."""
        attributes: dict[str, str | bytes] = {
            **self.flash_attributes(),
            "device/of_node/compatible": b"ibm,opal-flash-v2\0ibm,opal-flash\0",
        }
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = self.make_sysfs(Path(tmp), {"mtd12": attributes, "mtd12ro": {"dev": "90:25"}})
            self.assertEqual(fsa.find_flash_mtd(sysfs).index, 12)

    def partition_attributes(self, name: str, base: int, size: int, minor: int) -> dict[str, str | bytes]:
        """Return the sysfs attributes of a partition MTD of the OPAL flash, as mtdpart.c exposes them."""
        return {
            "name": name,
            "size": str(size),
            "erasesize": "4096",
            "flags": "0x400" if name == "PNOR" else "0x0",
            "dev": f"90:{minor}",
            "type": "nor",
            "offset": str(base),
            "device/of_node/compatible": b"ibm,opal-flash\0",
        }

    def new_firmware_mtds(self) -> dict[str, dict[str, str | bytes]]:
        """Return the MTDs Debian registers under the new skiboot: PNOR, then four read-only partitions.

        skiboot sorts the partition nodes by unit address, so partition@0, the
        whole-flash PNOR, comes first and takes the lowest free index.
        """
        devices: dict[str, dict[str, str | bytes]] = {
            "mtd0": {"name": "enP1p1s0f0 sfc_mcfw:00", "size": "1048576", "erasesize": "65536",
                     "dev": "90:0", "type": "nor"},
            "mtd0ro": {"dev": "90:1"},
        }
        for index, (name, base, size) in enumerate(
            (
                ("PNOR", 0, cp.IMAGE_SIZE),
                ("BOOTKERNEL", 0xDA9000, 0xF00000),
                ("CAPP", 0x1E7E000, 0x24000),
                ("IMA_CATALOG", 0x1EC6000, 0x9000),
                ("VERSION", 0x1FF7000, 0x1000),
            ),
            6,
        ):
            devices[f"mtd{index}"] = self.partition_attributes(name, base, size, 2 * index)
            devices[f"mtd{index}ro"] = {"dev": f"90:{2 * index + 1}"}
        return devices

    def test_resolves_pnor_partition_of_new_firmware(self) -> None:
        """Without flash@0, the 64 MiB PNOR partition at offset 0 is the flash; smaller ones are ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysfs = self.make_sysfs(root, self.new_firmware_mtds())
            info = fsa.find_flash_mtd(sysfs)
            self.assertEqual((info.index, info.name, info.offset), (6, "PNOR", 0))
            self.assertEqual((info.size, info.erasesize, info.flags), (cp.IMAGE_SIZE, 0x1000, 0x400))
            self.assertEqual((info.dev, info.ro_dev), ((90, 12), (90, 13)))
            real_stat = os.stat

            def fake_stat(path: str | os.PathLike[str], *, follow_symlinks: bool = True) -> os.stat_result:
                """Present /dev/mtd6 and /dev/mtd6ro as the character devices sysfs names."""
                minor = {"mtd6": 12, "mtd6ro": 13}.get(Path(path).name)
                if minor is None:
                    return real_stat(path, follow_symlinks=follow_symlinks)
                return os.stat_result(
                    (stat.S_IFCHR | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0), {"st_rdev": os.makedev(90, minor)}
                )

            with mock.patch.object(fsa.os, "stat", fake_stat):
                device, _info = fsa.open_mtd(fsa.SystemPaths(sysfs, root / "dev", root / "proc", "systemctl"))
            self.assertEqual(
                device.label, f"{root / 'dev' / 'mtd6'} (PNOR, read back through {root / 'dev' / 'mtd6ro'})"
            )

    def test_refuses_pnor_that_is_not_the_whole_opal_flash(self) -> None:
        """PNOR at a non-zero offset, PNOR beside flash@0, or a PNOR not under ibm,opal-flash is refused."""
        moved = self.new_firmware_mtds()
        moved["mtd6"] = {**moved["mtd6"], "offset": "4096"}
        both = self.new_firmware_mtds()
        both["mtd12"] = self.flash_attributes()
        both["mtd12ro"] = {"dev": "90:25"}
        foreign = self.new_firmware_mtds()
        foreign["mtd6"] = {**foreign["mtd6"], "device/of_node/compatible": b"jedec,spi-nor\0"}
        cases: dict[str, tuple[dict[str, dict[str, str | bytes]], str]] = {
            "offset": (moved, "mtd6 'PNOR' is a partition at offset 0x1000, not at 0x0"),
            "two": (both, "^2 MTDs .* expected exactly one"),
            "foreign": (foreign, "mtd6 'PNOR''s device-tree node is compatible with \\[jedec,spi-nor\\]"),
        }
        for label, (devices, message) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                sysfs = self.make_sysfs(Path(tmp), devices)
                with self.assertRaisesRegex(fsa.DeviceError, message) as raised:
                    fsa.find_flash_mtd(sysfs)
                self.assertIn("mtd7 'BOOTKERNEL' of 0xf00000 bytes at offset 0xda9000", str(raised.exception))
                self.assertIn("mtd0 'enP1p1s0f0 sfc_mcfw:00' of 0x100000 bytes", str(raised.exception))

    def test_recovery_command_is_runnable_as_printed(self) -> None:
        """Run as root the printed command starts with sudo; run as another user it does not."""
        script = str(Path(fsa.__file__).resolve())
        words = ("rollback", "--stage", "toc")
        for euid, prefix in ((0, ["sudo"]), (1000, [])):
            with self.subTest(euid=euid), mock.patch.object(fsa.os, "geteuid", lambda: euid):
                self.assertEqual(fsa._self_command(*words), shlex.join([*prefix, "python3", script, *words]))

    def test_ignored_signal_stays_ignored(self) -> None:
        """A signal set to SIG_IGN keeps being ignored while the others are held."""
        reset_held_signals(self)
        previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        try:
            with fsa.DeferredSignals() as signals:
                self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
                os.kill(os.getpid(), signal.SIGHUP)
                self.assertIsNone(signals.received)
                os.kill(os.getpid(), signal.SIGTERM)
                self.assertEqual(signals.received, signal.SIGTERM)
            self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGHUP, previous)

    def test_device_nodes_must_be_character_devices(self) -> None:
        """A regular file standing in for /dev/mtdN is refused."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysfs = self.make_sysfs(root, {"mtd6": self.flash_attributes(), "mtd6ro": {"dev": "90:13"}})
            dev = root / "dev"
            dev.mkdir()
            (dev / "mtd6").write_bytes(b"")
            (dev / "mtd6ro").write_bytes(b"")
            with self.assertRaisesRegex(fsa.DeviceError, "not a character device"):
                fsa.open_mtd(fsa.SystemPaths(sysfs, dev, root / "proc", "systemctl"))

    def test_opal_prd_guard(self) -> None:
        """An active opal-prd unit or process is reported; an inactive one is not."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            (proc / "1").mkdir(parents=True)
            (proc / "1" / "comm").write_text("systemd\n", encoding="ascii")
            for state, expected in (("active", 1), ("inactive", 0), ("failed", 0), ("activating", 1)):
                with self.subTest(state=state):
                    systemctl = root / f"systemctl-{state}"
                    systemctl.write_text(f"#!/bin/sh\necho {state}\n", encoding="ascii")
                    systemctl.chmod(0o755)
                    problems = fsa.opal_prd_problems(fsa.SystemPaths(root, root, proc, str(systemctl)))
                    self.assertEqual(len(problems), expected, problems)
            (proc / "4242").mkdir()
            (proc / "4242" / "comm").write_text("opal-prd\n", encoding="ascii")
            inactive = str(root / "systemctl-inactive")
            problems = fsa.opal_prd_problems(fsa.SystemPaths(root, root, proc, inactive))
            self.assertEqual(problems, ["an opal-prd process is running (pid 4242)"])
            missing = fsa.opal_prd_problems(fsa.SystemPaths(root, root, root / "none", str(root / "absent")))
            self.assertEqual(len(missing), 1)

    def test_yes_is_mandatory(self) -> None:
        """flash and rollback refuse to start without --yes."""
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            fsa.main(["rollback", "--stage", "toc", "--backup", "b", "--log", "l", "--device", "i"])
        self.assertEqual(raised.exception.code, fsa.EXIT_USAGE)


class DeviceReadTest(unittest.TestCase):
    """Device.read assembles its bytes from os.pread calls at explicit offsets."""

    def setUp(self) -> None:
        """Write an image a little over three read chunks long."""
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.content = hashlib.shake_256(b"device read").digest(3 * fsa.READ_CHUNK + 0x1234)
        self.path = self.tmp / "image.bin"
        self.path.write_bytes(self.content)
        self.device = fsa.Device("test image", self.path, self.path)

    def test_partial_preads_assemble_exactly(self) -> None:
        """Short reads are continued at exactly the next offset, in chunks of at most READ_CHUNK."""
        calls: list[tuple[int, int, int]] = []

        def short_pread(descriptor: int, length: int, offset: int) -> bytes:
            """Return a little over half of what was asked for, as an interrupted MTD read may."""
            chunk = self.content[offset : offset + min(length, length // 2 + 7)]
            calls.append((offset, length, len(chunk)))
            return chunk

        base, size = 0x777, len(self.content) - 0x777 - 5
        with mock.patch.object(fsa.os, "pread", short_pread):
            data = self.device.read(base, size)
        self.assertTrue(data == self.content[base : base + size], "the assembled bytes differ")
        self.assertEqual(calls[0][0], base)
        for (offset, length, returned), following in zip(calls, calls[1:]):
            self.assertEqual(following[0], offset + returned)
        last_offset, last_length, last_returned = calls[-1]
        self.assertEqual(last_offset + last_returned, base + size)
        for offset, length, returned in calls:
            self.assertTrue(0 < length <= fsa.READ_CHUNK, length)
            self.assertTrue(0 < returned <= length)
            self.assertEqual(length, min(fsa.READ_CHUNK, base + size - offset))

    def test_whole_chunks(self) -> None:
        """Without short reads every request is one READ_CHUNK at the next chunk boundary."""
        calls: list[tuple[int, int]] = []
        real_pread = os.pread

        def recording_pread(descriptor: int, length: int, offset: int) -> bytes:
            """Record the request and read for real."""
            calls.append((offset, length))
            return real_pread(descriptor, length, offset)

        with mock.patch.object(fsa.os, "pread", recording_pread):
            data = self.device.read(0, len(self.content))
        self.assertTrue(data == self.content, "the assembled bytes differ")
        chunk = fsa.READ_CHUNK
        self.assertEqual(calls, [(0, chunk), (chunk, chunk), (2 * chunk, chunk), (3 * chunk, 0x1234)])

    def test_empty_pread_is_a_short_read(self) -> None:
        """A pread returning no bytes before the end is a DeviceError naming the offset."""
        calls: list[int] = []

        def failing_pread(descriptor: int, length: int, offset: int) -> bytes:
            """Return one full chunk, then nothing."""
            calls.append(offset)
            return self.content[offset : offset + length] if len(calls) == 1 else b""

        with mock.patch.object(fsa.os, "pread", failing_pread):
            with self.assertRaisesRegex(
                fsa.DeviceError, f"short read from .* at 0x{fsa.READ_CHUNK:x} \\({fsa.READ_CHUNK} of"
            ):
                self.device.read(0, len(self.content))
        self.assertEqual(calls, [0, fsa.READ_CHUNK])


class SyntheticData:
    """A synthetic kit and backup shared by the synthetic test classes."""

    workspace: tempfile.TemporaryDirectory[str] | None = None
    kit: Path
    backup: Path

    @classmethod
    def get(cls) -> tuple[Path, Path]:
        """Build the kit and the backup once per test run."""
        if cls.workspace is None:
            cls.workspace = tempfile.TemporaryDirectory(prefix="test_flash_side_a-")
            root = Path(cls.workspace.name)
            cls.kit = root / "kit"
            cut_synthetic_kit(cls.kit)
            cls.backup = root / "backup.bin"
            cls.backup.write_bytes(synthetic_backup())
        return cls.kit, cls.backup


def tearDownModule() -> None:
    """Remove the shared synthetic data."""
    if SyntheticData.workspace is not None:
        SyntheticData.workspace.cleanup()
        SyntheticData.workspace = None


class KitTest(unittest.TestCase):
    """verify-kit on a good kit and on kits broken in one place each."""

    kit: Path
    backup: Path

    @classmethod
    def setUpClass(cls) -> None:
        """Use the shared synthetic kit."""
        cls.kit, cls.backup = SyntheticData.get()

    def setUp(self) -> None:
        """Give each test a private copy of the kit and a fresh image."""
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.copy = self.tmp / "kit"
        shutil.copytree(self.kit, self.copy)
        self.image = self.tmp / "image.bin"
        shutil.copyfile(self.backup, self.image)

    def assertKitViolation(self, needle: str) -> None:
        """Assert that verify-kit fails with ``needle`` and that flash then writes nothing."""
        report, kit = fsa.verify_kit(self.copy)
        self.assertIsNone(kit)
        self.assertTrue(any(needle in violation for violation in report.violations), report.render())
        pflash = make_fake_pflash(self.tmp / "bin")
        status, output = run_main(
            ["flash", str(self.copy), "--stage", "hostboot", "--backup", str(self.backup), "--device",
             str(self.image), "--log", str(self.tmp / "log"), "--pflash", str(pflash.path), "--yes"]
        )
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertEqual(pflash.calls(), [])
        self.assertEqual(self.image.read_bytes(), self.backup.read_bytes())

    def test_good_kit(self) -> None:
        """The kit check_pnor cuts verifies cleanly and the CLI agrees."""
        report, kit = fsa.verify_kit(self.copy)
        self.assertEqual(report.violations, [], report.render())
        self.assertIsNotNone(kit)
        if kit is not None:
            self.assertEqual([item.name for item in fsa.kit_items(kit, fsa.Stage.HOSTBOOT)], HOSTBOOT_ORDER)
            toc_names = [item.name for item in fsa.kit_items(kit, fsa.Stage.TOC)]
            self.assertEqual(toc_names, ["toc0.bin", "toc1.bin"])
        self.assertEqual(run_main(["verify-kit", str(self.copy)])[0], fsa.EXIT_OK)

    def test_range_in_side_b(self) -> None:
        """A manifest that puts HBI into side B is refused."""
        edit_manifest(self.copy, set_field("partitions", ("name", "HBI"), "base", 0x2188000))
        self.assertKitViolation("side B is never written")

    def test_range_overlapping_guard(self) -> None:
        """A manifest that puts HBD over GUARD is refused."""
        edit_manifest(self.copy, set_field("partitions", ("name", "HBD"), "base", 0x2C000))
        self.assertKitViolation("overlaps protected partition GUARD")

    def test_do_not_write_cannot_shrink_protection(self) -> None:
        """Dropping GUARD from do_not_write is refused and GUARD stays fenced."""

        def drop_guard(manifest: dict[str, object]) -> None:
            """Remove GUARD from the do_not_write list."""
            manifest["do_not_write"] = [
                item for item in as_array(manifest["do_not_write"]) if as_record(item).get("name") != "GUARD"
            ]

        edit_manifest(self.copy, drop_guard)
        self.assertKitViolation("do_not_write")

    def test_digest_mismatch(self) -> None:
        """A partition file that no longer matches SHA256SUMS is refused."""
        blob = bytearray((self.copy / "HBB.bin").read_bytes())
        blob[100] ^= 0xFF
        (self.copy / "HBB.bin").write_bytes(bytes(blob))
        self.assertKitViolation("HBB.bin: SHA-256")

    def test_file_size_must_equal_partition_size(self) -> None:
        """A partition file shorter than its partition is refused even when resealed."""
        short = (self.copy / "PAYLOAD.bin").read_bytes()[:-0x1000]
        (self.copy / "PAYLOAD.bin").write_bytes(short)
        digest = hashlib.sha256(short).hexdigest()
        edit_manifest(self.copy, set_field("partitions", ("name", "PAYLOAD"), "sha256", digest))
        self.assertKitViolation("PAYLOAD.bin is 1044480 bytes, the partition is 1048576")

    def test_partition_file_must_be_named_after_it(self) -> None:
        """A manifest pointing HBB at SBEC.bin, the same size and digest-consistent, is refused."""
        sbec = hashlib.sha256((self.copy / "SBEC.bin").read_bytes()).hexdigest()
        edit_manifest(self.copy, set_field("partitions", ("name", "HBB"), "file", "SBEC.bin"))
        edit_manifest(self.copy, set_field("partitions", ("name", "HBB"), "sha256", sbec))
        self.assertKitViolation("partition HBB: file SBEC.bin is not HBB.bin")

    def test_toc_moving_guard(self) -> None:
        """A toc0.bin that moves GUARD is refused."""
        entries = tcp.replace_entry(tcp.decided_side_a_entries(), "GUARD", base=0x2D000)
        blob = tcp.serialise_toc(entries)
        (self.copy / "toc0.bin").write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        edit_manifest(self.copy, set_field("tocs", ("file", "toc0.bin"), "sha256", digest))
        self.assertKitViolation("toc0.bin: GUARD is 0x002d000..0x0032000, expected 0x002c000..0x0031000")


class FlowBase(unittest.TestCase):
    """Flash and rollback flows on a copy of a backup; subclasses supply the data."""

    kit_dir: Path
    backup_path: Path
    backup: bytes
    kit: fsa.Kit

    @classmethod
    def provide(cls) -> tuple[Path, Path]:
        """Return the kit directory and the backup file to run the flows on."""
        raise unittest.SkipTest("FlowBase only holds the flow tests")

    @classmethod
    def setUpClass(cls) -> None:
        """Load and verify the data once per class."""
        cls.kit_dir, cls.backup_path = cls.provide()
        cls.backup = cls.backup_path.read_bytes()
        report, kit = fsa.verify_kit(cls.kit_dir)
        if kit is None:
            raise AssertionError(report.render())
        cls.kit = kit

    def setUp(self) -> None:
        """Copy the backup into a fresh image for each test."""
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="test_flash_side_a-")))
        self.image = self.tmp / "image.bin"
        shutil.copyfile(self.backup_path, self.image)
        self.log = self.tmp / "flash.log"
        self.sleeps: list[float] = []
        reset_held_signals(self)

    def flash(self, stage: str, pflash: FakePflash) -> tuple[int, str]:
        """Run one flash stage on the test image, recording retry delays instead of sleeping."""
        return run_main(
            ["flash", str(self.kit_dir), "--stage", stage, "--backup", str(self.backup_path),
             "--device", str(self.image), "--log", str(self.log), "--pflash", str(pflash.path), "--yes"],
            self.sleeps.append,
        )

    def rollback(self, stage: str, pflash: FakePflash) -> tuple[int, str]:
        """Run one rollback stage on the test image, recording retry delays instead of sleeping."""
        return run_main(
            ["rollback", "--stage", stage, "--backup", str(self.backup_path), "--device", str(self.image),
             "--log", str(self.log), "--pflash", str(pflash.path), "--yes"],
            self.sleeps.append,
        )

    def patch_image(self, offset: int, data: bytes) -> None:
        """Overwrite bytes of the test image in place."""
        with open(self.image, "r+b") as handle:
            handle.seek(offset)
            handle.write(data)

    def items(self, stage: fsa.Stage) -> list[fsa.WriteItem]:
        """Return the kit's items for ``stage``."""
        return fsa.kit_items(self.kit, stage)

    def differing(self, stage: fsa.Stage) -> list[fsa.WriteItem]:
        """Return the items of ``stage`` that the backup does not already hold."""
        return [item for item in self.items(stage) if self.backup[item.base : item.end] != item.data]

    def assertUntouched(self) -> None:
        """Assert that the image is still exactly the backup."""
        self.assertTrue(self.image.read_bytes() == self.backup, "the image no longer equals the backup")

    def test_full_sequence_then_rollback(self) -> None:
        """hostboot, toc and bootkernel give the kit's side A; three rollbacks give the backup back."""
        pflash = make_fake_pflash(self.tmp / "bin")
        for stage in ("hostboot", "toc", "bootkernel"):
            status, output = self.flash(stage, pflash)
            self.assertEqual(status, fsa.EXIT_OK, output)
            self.assertIn(fsa.FLASH_NEXT[fsa.Stage(stage)], output)
        image = self.image.read_bytes()
        self.assertEqual(image[: cp.TOC_BLOCK_BYTES], self.kit.toc0)
        self.assertEqual(image[cp.BACKUP_TOC : cp.BACKUP_TOC + cp.TOC_BLOCK_BYTES], self.kit.toc1)
        self.assertEqual(cp.parse_toc(image, cp.PRIMARY_TOC).entries, self.kit.toc0_parsed.entries)
        self.assertTrue(image[cp.SIDE_SIZE :] == self.backup[cp.SIDE_SIZE :], "side B changed")
        for name, (base, size) in fsa.LIVE_PROTECTED.items():
            self.assertTrue(image[base : base + size] == self.backup[base : base + size], f"{name} changed")
        written = sorted(
            (item.base, item.end)
            for stage in fsa.Stage
            for item in self.items(stage)
        )
        cursor = 0
        for base, end in [*written, (cp.IMAGE_SIZE, cp.IMAGE_SIZE)]:
            unchanged = image[cursor:base] == self.backup[cursor:base]
            self.assertTrue(unchanged, f"0x{cursor:x}..0x{base:x} changed")
            cursor = end
        for stage in fsa.Stage:
            for item in self.items(stage):
                self.assertTrue(image[item.base : item.end] == item.data, f"{item.name} not written")
        report, _toc = cp.run_check(image, FIXTURES)
        self.assertEqual(report.violations, [], report.render())
        for call in pflash.writes():
            self.assertNotIn("-P", call)
            flags = [call[index] for index in (0, 2, 3, 4, 6, 8)]
            self.assertEqual(flags, ["-F", "-f", "-e", "-a", "-s", "-p"])
            self.assertEqual(call[1], str(self.image.resolve()))
        expected_writes = sum(len(self.differing(stage)) for stage in fsa.Stage)
        self.assertEqual(len(pflash.writes()), expected_writes)

        for stage in ("bootkernel", "toc", "hostboot"):
            status, output = self.rollback(stage, pflash)
            self.assertEqual(status, fsa.EXIT_OK, output)
            self.assertIn(fsa.ROLLBACK_NEXT[fsa.Stage(stage)], output)
        self.assertUntouched()

    def test_second_run_skips_everything(self) -> None:
        """Re-running a completed stage writes nothing."""
        pflash = make_fake_pflash(self.tmp / "bin")
        self.assertEqual(self.flash("hostboot", pflash)[0], fsa.EXIT_OK)
        before = len(pflash.writes())
        self.assertEqual(before, len(self.differing(fsa.Stage.HOSTBOOT)))
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_OK, output)
        self.assertEqual(len(pflash.writes()), before)
        self.assertIn(f"0 written (none), {len(HOSTBOOT_ORDER)} already identical", output)

    def test_stage_order_enforced(self) -> None:
        """toc before hostboot and bootkernel before toc are refused without writing."""
        pflash = make_fake_pflash(self.tmp / "bin")
        status, output = self.flash("toc", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("stage toc needs the hostboot stage fully on the device", output)
        status, output = self.flash("bootkernel", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("stage bootkernel needs both TOC blocks to be the kit's", output)
        self.assertEqual(pflash.writes(), [])
        self.assertUntouched()

    def test_unrecognised_toc_refused(self) -> None:
        """A TOC@0x0 that is neither the backup's nor the kit's stops every stage."""
        self.patch_image(0x40, b"\x5a")
        pflash = make_fake_pflash(self.tmp / "bin")
        for stage in ("hostboot", "toc", "bootkernel"):
            with self.subTest(stage=stage):
                status, output = self.flash(stage, pflash)
                self.assertEqual(status, fsa.EXIT_REFUSED, output)
                self.assertIn("neither the backup's nor the kit's TOC blocks", output)
        self.assertEqual(pflash.writes(), [])

    def test_readback_mismatch_retries_then_aborts(self) -> None:
        """A write that never reads back right is retried once, then the run aborts loudly."""
        pflash = make_fake_pflash(self.tmp / "bin", "corrupt")
        first = self.differing(fsa.Stage.HOSTBOOT)[0]
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        writes = pflash.writes()
        self.assertEqual(len(writes), fsa.WRITE_ATTEMPTS)
        self.assertTrue(all(call[5] == f"0x{first.base:x}" for call in writes))
        self.assertEqual(self.sleeps, [fsa.RETRY_DELAY_SECONDS])
        self.assertIn(f"{first.name}: waiting {fsa.RETRY_DELAY_SECONDS} s before attempt 2", output)
        self.assertIn(f"ABORT: {first.name} {fsa._span(first.base, first.size)} failed 2 attempts", output)
        self.assertIn("now holds neither the intended nor the backup's bytes", output)
        self.assertIn("written and verified in this run: none", output)
        image = self.image.read_bytes()
        self.assertTrue(image[first.end :] == self.backup[first.end :])
        self.assertIn("ABORT", self.log.read_text(encoding="utf-8"))
        status, output = self.rollback("hostboot", make_fake_pflash(self.tmp / "good"))
        self.assertEqual(status, fsa.EXIT_OK, output)
        self.assertUntouched()

    def test_readback_mismatch_once_recovers(self) -> None:
        """A single bad read-back is cured by the retry."""
        pflash = make_fake_pflash(self.tmp / "bin", "corrupt-once")
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_OK, output)
        self.assertEqual(len(pflash.writes()), len(self.differing(fsa.Stage.HOSTBOOT)) + 1)
        self.assertIn("attempt 1 failed: pflash exited 0 but the read-back differs", output)
        self.assertEqual(self.sleeps, [fsa.RETRY_DELAY_SECONDS])
        log = self.log.read_text(encoding="utf-8")
        failed = log.index("attempt 1 failed")
        self.assertLess(failed, log.index("waiting 10 s before attempt 2"))
        self.assertLess(log.index("waiting 10 s before attempt 2"), log.index(": attempt 2: "))

    def test_pflash_error_status_aborts(self) -> None:
        """A non-zero pflash status is a failure even before the read-back."""
        pflash = make_fake_pflash(self.tmp / "bin", "fail")
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        self.assertEqual(len(pflash.writes()), fsa.WRITE_ATTEMPTS)
        self.assertEqual(self.sleeps, [fsa.RETRY_DELAY_SECONDS])
        self.assertIn("pflash exited with status 8", output)
        self.assertIn("pflash stderr: Flash write error 8", output)
        self.assertIn("now holds erased flash (every byte 0xff)", output)

    def test_sigquit_finishes_current_item(self) -> None:
        """SIGQUIT (Ctrl-\\) is held like SIGTERM instead of killing the run mid-item."""
        pflash = make_fake_pflash(self.tmp / "bin", "sigquit")
        first, second = self.differing(fsa.Stage.HOSTBOOT)[:2]
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        self.assertIn(f"stopped by signal SIGQUIT before {second.name}", output)
        self.assertIn(f"written and verified in this run: {first.name}", output)
        self.assertEqual(signal.getsignal(signal.SIGQUIT), signal.SIG_DFL)

    def test_stray_write_caught_by_post_check(self) -> None:
        """A pflash that also changes a TOC field or a byte outside every item fails the post-check."""
        for label, offset in (("TOC@0x0 actual size of 'part'", 0x5A), ("gap after IMA_CATALOG", 0x1ECF000)):
            with self.subTest(where=label):
                shutil.copyfile(self.backup_path, self.image)
                pflash = make_fake_pflash(self.tmp / label.replace(" ", "_"), f"stray:0x{offset:x}")
                status, output = self.flash("hostboot", pflash)
                self.assertEqual(status, fsa.EXIT_ABORTED, output)
                block = offset - offset % cp.BLOCK_SIZE
                self.assertIn(
                    f"ABORT: post-check: {fsa._span(block, cp.BLOCK_SIZE)} changed during this run "
                    "although it was not written",
                    output,
                )
                self.assertNotIn("done:", output)

    def test_guard_stops_before_next_item(self) -> None:
        """An opal-prd that starts during the run stops it before the next item."""
        pflash = make_fake_pflash(self.tmp / "bin")
        items = self.differing(fsa.Stage.HOSTBOOT)
        checks: list[int] = []

        def guard() -> list[str]:
            """Report opal-prd from the third check on, the first one of the second item."""
            checks.append(len(checks))
            return [] if len(checks) <= 2 else ["an opal-prd process is running (pid 4242)"]

        with fsa.ActionLog(self.log, io.StringIO()) as log, fsa.DeferredSignals() as signals:
            flasher = fsa.Flasher(
                fsa.open_image(self.image, None), pflash.path, fsa.WriteFence(), log, self.tmp, signals,
                self.backup, guard, refuse_sleep,
            )
            with self.assertRaises(fsa.FlashAborted) as raised:
                flasher.apply(items)
        message = str(raised.exception)
        self.assertIn(
            f"precondition no longer holds: an opal-prd process is running (pid 4242) before {items[1].name}",
            message,
        )
        self.assertIn(f"written and verified in this run: {items[0].name}", message)
        self.assertEqual(len(pflash.writes()), 1)

    def test_log_failure_stops_before_next_item(self) -> None:
        """A log file that can no longer be written lets the current item verify, then stops the run."""
        pflash = make_fake_pflash(self.tmp / "bin")
        items = self.differing(fsa.Stage.HOSTBOOT)
        out = io.StringIO()
        with fsa.ActionLog(self.log, out) as log, fsa.DeferredSignals() as signals:
            checks: list[int] = []

            def guard() -> list[str]:
                """Fill the disk under the log at the fourth check, just before the second item is written."""
                checks.append(len(checks))
                if len(checks) == 4 and log._file is not None:
                    log._file.close()
                    log._file = FullDisk()
                return []

            flasher = fsa.Flasher(
                fsa.open_image(self.image, None), pflash.path, fsa.WriteFence(), log, self.tmp, signals,
                self.backup, guard, refuse_sleep,
            )
            with self.assertRaises(fsa.FlashAborted) as raised:
                flasher.apply(items)
        self.assertIn(f"writing the log file failed: [Errno {errno.ENOSPC}]", out.getvalue())
        self.assertIn(f"before {items[2].name}", str(raised.exception))
        self.assertIn(f"{items[1].name} {fsa._span(items[1].base, items[1].size)}: written and read back", out.getvalue())
        self.assertEqual(len(pflash.writes()), 2)

    def test_log_must_be_a_regular_file_other_than_backup_and_image(self) -> None:
        """--log naming a device node, the backup or the image is refused before anything is touched."""
        backup = self.tmp / "backup-copy.bin"
        shutil.copyfile(self.backup_path, backup)
        pflash = make_fake_pflash(self.tmp / "bin")
        for label, log, needle in (
            ("device node", Path(os.devnull), "is not a regular file"),
            ("backup", backup, f"is the same file as {backup.resolve()}"),
            ("image", self.image, f"is the same file as {self.image}"),
        ):
            with self.subTest(log=label):
                status, output = run_main(
                    ["flash", str(self.kit_dir), "--stage", "hostboot", "--backup", str(backup), "--device",
                     str(self.image), "--log", str(log), "--pflash", str(pflash.path), "--yes"]
                )
                self.assertEqual(status, fsa.EXIT_REFUSED, output)
                self.assertIn(needle, output)
                self.assertTrue(backup.read_bytes() == self.backup, "the backup was modified")
                self.assertUntouched()
        self.assertEqual(pflash.calls(), [])

    def test_backup_must_be_a_regular_file(self) -> None:
        """A device node given as the backup is refused."""
        pflash = make_fake_pflash(self.tmp / "bin")
        status, output = run_main(
            ["rollback", "--stage", "toc", "--backup", os.devnull, "--device", str(self.image),
             "--log", str(self.log), "--pflash", str(pflash.path), "--yes"]
        )
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn(f"the backup {os.devnull} is not a regular file", output)
        self.assertEqual(pflash.calls(), [])
        self.assertUntouched()

    def test_signal_finishes_current_item(self) -> None:
        """SIGTERM during a write lets that item verify, then stops before the next one."""
        pflash = make_fake_pflash(self.tmp / "bin", "signal")
        first, second = self.differing(fsa.Stage.HOSTBOOT)[:2]
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        self.assertIn(f"stopped by signal SIGTERM before {second.name}", output)
        self.assertIn(f"written and verified in this run: {first.name}", output)
        self.assertEqual(len(pflash.writes()), 1)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_runtime_partitions_may_drift(self) -> None:
        """GUARD, NVRAM and MVPD drift is reported and flash and rollback both run; side-B drift refuses."""
        pflash = make_fake_pflash(self.tmp / "bin")
        guard = fsa.LIVE_PROTECTED["GUARD"][0]
        nvram = fsa.LIVE_PROTECTED["NVRAM"][0]
        mvpd = fsa.LIVE_PROTECTED["MVPD"][0]
        self.patch_image(guard + 0x10, b"\x00\x01")
        self.patch_image(nvram + 0x100, b"drift")
        self.patch_image(mvpd + 0x20, bytes([self.backup[mvpd + 0x20] ^ 0x42]))
        for run in (self.flash, self.rollback):
            with self.subTest(run=run.__name__):
                status, output = run("hostboot", pflash)
                self.assertEqual(status, fsa.EXIT_OK, output)
                self.assertIn("note: GUARD", output)
                self.assertIn("note: NVRAM", output)
                self.assertIn(
                    f"note: MVPD {fsa._span(mvpd, fsa.LIVE_PROTECTED['MVPD'][1])} differs from the backup "
                    "(hostboot rewrites this VPD cache at IPL; the backup's copy is stale and no stage ever "
                    "writes or restores it)",
                    output,
                )
                self.assertNotIn("REFUSED", output)
        image = self.image.read_bytes()
        self.assertEqual(image[mvpd + 0x20], self.backup[mvpd + 0x20] ^ 0x42)
        for name, (base, size) in fsa.LIVE_CODE.items():
            restored = image[base : base + size] == self.backup[base : base + size]
            self.assertTrue(restored, f"{name} not restored")
        shutil.copyfile(self.backup_path, self.image)
        self.patch_image(0x2800000, b"\x42")
        before = len(pflash.writes())
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("REFUSED: side B", output)
        self.assertEqual(len(pflash.writes()), before)

    def test_rollback_hostboot_needs_old_toc(self) -> None:
        """Hostboot is only rolled back once the live TOC blocks are back."""
        pflash = make_fake_pflash(self.tmp / "bin")
        for stage in ("hostboot", "toc"):
            self.assertEqual(self.flash(stage, pflash)[0], fsa.EXIT_OK)
        before = len(pflash.writes())
        status, output = self.rollback("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("roll back the bootkernel and toc stages first", output)
        self.assertEqual(len(pflash.writes()), before)

    def test_interrupted_toc_stage(self) -> None:
        """A toc stage stopped after TOC@0x0 resumes with TOC@0x1ff8000; hostboot is refused meanwhile."""
        pflash = make_fake_pflash(self.tmp / "bin")
        self.assertEqual(self.flash("hostboot", pflash)[0], fsa.EXIT_OK)
        self.patch_image(cp.PRIMARY_TOC, self.kit.toc0)
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("the toc stage was interrupted", output)
        before = len(pflash.writes())
        status, output = self.flash("toc", pflash)
        self.assertEqual(status, fsa.EXIT_OK, output)
        self.assertEqual([call[5] for call in pflash.writes()[before:]], [f"0x{cp.BACKUP_TOC:x}"])
        self.assertIn("TOC blocks now post-switch", output)

    def test_damaged_toc_repaired_by_rollback(self) -> None:
        """An erased TOC@0x0 refuses flash but rollback --stage toc restores it."""
        self.patch_image(cp.PRIMARY_TOC, b"\xff" * cp.TOC_BLOCK_BYTES)
        pflash = make_fake_pflash(self.tmp / "bin")
        self.assertEqual(self.flash("toc", pflash)[0], fsa.EXIT_REFUSED)
        status, output = self.rollback("toc", pflash)
        self.assertEqual(status, fsa.EXIT_OK, output)
        self.assertUntouched()

    def test_image_must_not_be_the_backup(self) -> None:
        """The backup itself is never accepted as the device."""
        pflash = make_fake_pflash(self.tmp / "bin")
        status, output = run_main(
            ["flash", str(self.kit_dir), "--stage", "hostboot", "--backup", str(self.image),
             "--device", str(self.image), "--log", str(self.log), "--pflash", str(pflash.path), "--yes"]
        )
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("is the backup itself", output)
        self.assertEqual(pflash.writes(), [])
        self.assertUntouched()

    def test_log_records_everything_with_timestamps(self) -> None:
        """Every log line is timestamped and the log names the backup digest and each command."""
        pflash = make_fake_pflash(self.tmp / "bin")
        self.assertEqual(self.flash("bootkernel", pflash)[0], fsa.EXIT_REFUSED)
        self.assertEqual(self.flash("hostboot", pflash)[0], fsa.EXIT_OK)
        lines = self.log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, TIMESTAMP)
        text = "\n".join(lines)
        self.assertIn(f"sha256 {hashlib.sha256(self.backup).hexdigest()}", text)
        self.assertIn("REFUSED: stage bootkernel", text)
        self.assertIn(" -F ", text)
        self.assertIn("pflash stdout: [==================================================] 100%", text)
        self.assertNotIn("] 0%", text)

    def test_plan(self) -> None:
        """plan lists the stage in order and marks what the device already holds."""
        plan = ["plan", str(self.kit_dir), "--device", str(self.image), "--stage"]
        status, output = run_main([*plan, "hostboot"])
        self.assertEqual(status, fsa.EXIT_OK, output)
        names = re.findall(r"^\s+\d+\. (\S+)", output, re.MULTILINE)
        self.assertEqual(names, HOSTBOOT_ORDER)
        self.assertIn("pre-switch", output)
        skipped = len(HOSTBOOT_ORDER) - len(self.differing(fsa.Stage.HOSTBOOT))
        self.assertIn(f"{len(HOSTBOOT_ORDER) - skipped} to write, {skipped} already identical", output)
        status, output = run_main([*plan, "bootkernel"])
        self.assertIn("flash would refuse: stage bootkernel", output)


class SyntheticFlowTest(FlowBase):
    """The flows on the synthetic kit and backup."""

    @classmethod
    def provide(cls) -> tuple[Path, Path]:
        """Use the shared synthetic data."""
        return SyntheticData.get()

    def test_firmware_maintained_change_during_run_is_fatal(self) -> None:
        """MVPD changing while a stage runs fails the post-check although MVPD drift is only a note."""
        mvpd = fsa.LIVE_PROTECTED["MVPD"][0]
        pflash = make_fake_pflash(self.tmp / "bin", f"stray:0x{mvpd + 0x20:x}")
        status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        self.assertIn(
            f"ABORT: post-check: {fsa._span(mvpd, cp.BLOCK_SIZE)} changed during this run "
            "although it was not written",
            output,
        )
        self.assertNotIn("note: MVPD", output)
        self.assertNotIn("done:", output)

    def test_signal_before_first_write_refuses(self) -> None:
        """A SIGINT during the pre-read refuses the run cleanly with nothing written."""
        pflash = make_fake_pflash(self.tmp / "bin")
        original = fsa.Device.read
        delivered: list[int] = []

        def read_then_interrupt(device: fsa.Device, base: int, size: int) -> bytes:
            """Read, and send SIGINT to this process during the first whole-device read."""
            data = original(device, base, size)
            if size == cp.IMAGE_SIZE and not delivered:
                delivered.append(signal.SIGINT)
                os.kill(os.getpid(), signal.SIGINT)
            return data

        handler = signal.getsignal(signal.SIGINT)
        with mock.patch.object(fsa.Device, "read", read_then_interrupt):
            status, output = self.flash("hostboot", pflash)
        self.assertEqual(delivered, [signal.SIGINT])
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn("REFUSED: signal SIGINT arrived: interrupted before any write", output)
        self.assertIn("nothing was written", output)
        self.assertNotIn("Traceback", output)
        self.assertEqual(pflash.writes(), [])
        self.assertEqual(signal.getsignal(signal.SIGINT), handler)
        self.assertUntouched()

    def interrupt_item_read(self, stage: str, pflash: FakePflash, nth: int) -> tuple[int, str]:
        """Run a flash stage and send SIGINT during the ``nth`` read of a single item, counting from 1."""
        original = fsa.Device.read
        item_reads: list[int] = []

        def read_then_interrupt(device: fsa.Device, base: int, size: int) -> bytes:
            """Read, and send SIGINT to this process during the ``nth`` read smaller than the device."""
            data = original(device, base, size)
            if size != cp.IMAGE_SIZE:
                item_reads.append(base)
                if len(item_reads) == nth:
                    os.kill(os.getpid(), signal.SIGINT)
            return data

        with mock.patch.object(fsa.Device, "read", read_then_interrupt):
            status, output = self.flash(stage, pflash)
        self.assertGreaterEqual(len(item_reads), nth)
        return status, output

    def test_signal_during_first_item_read_refuses(self) -> None:
        """A SIGINT while the first item is read before writing refuses the run; that item is not written."""
        for stage, earlier in (("hostboot", ()), ("bootkernel", ("hostboot", "toc"))):
            with self.subTest(stage=stage):
                shutil.copyfile(self.backup_path, self.image)
                pflash = make_fake_pflash(self.tmp / f"bin-{stage}")
                for previous in earlier:
                    status, output = self.flash(previous, pflash)
                    self.assertEqual(status, fsa.EXIT_OK, output)
                before = self.image.read_bytes()
                writes = len(pflash.writes())
                first = self.differing(fsa.Stage(stage))[0]
                handler = signal.getsignal(signal.SIGINT)
                status, output = self.interrupt_item_read(stage, pflash, 1)
                self.assertEqual(status, fsa.EXIT_REFUSED, output)
                self.assertIn(
                    f"REFUSED: stopped by signal SIGINT before {first.name}: interrupted before any write "
                    "(already identical, skipped: none)",
                    output,
                )
                self.assertIn("nothing was written", output)
                self.assertNotIn("ABORT", output)
                self.assertNotIn("Traceback", output)
                self.assertEqual(len(pflash.writes()), writes)
                self.assertTrue(self.image.read_bytes() == before, "the image changed")
                self.assertEqual(signal.getsignal(signal.SIGINT), handler)

    def test_signal_during_later_item_read_stops_before_that_item(self) -> None:
        """A SIGINT while the second item is read, after the first was written, aborts before the second."""
        pflash = make_fake_pflash(self.tmp / "bin")
        first, second = self.differing(fsa.Stage.HOSTBOOT)[:2]
        status, output = self.interrupt_item_read("hostboot", pflash, 3)
        self.assertEqual(status, fsa.EXIT_ABORTED, output)
        self.assertIn(f"ABORT: stopped by signal SIGINT before {second.name}", output)
        self.assertIn(f"written and verified in this run: {first.name}", output)
        self.assertEqual(len(pflash.writes()), 1)

    def test_item_read_failure_before_any_write_refuses(self) -> None:
        """A failed read of the first item before writing it refuses the run with nothing written."""
        pflash = make_fake_pflash(self.tmp / "bin")
        first = self.differing(fsa.Stage.HOSTBOOT)[0]
        original = fsa.Device.read

        def fail_item_read(device: fsa.Device, base: int, size: int) -> bytes:
            """Read the whole device, but fail every smaller read as an OPAL_BUSY would."""
            if size == cp.IMAGE_SIZE:
                return original(device, base, size)
            raise fsa.DeviceError(f"cannot read {device.readback} at 0x{base:x}: [Errno 16] Device or resource busy")

        with mock.patch.object(fsa.Device, "read", fail_item_read):
            status, output = self.flash("hostboot", pflash)
        self.assertEqual(status, fsa.EXIT_REFUSED, output)
        self.assertIn(f"REFUSED: cannot read {first.name} before writing it: cannot read", output)
        self.assertIn("nothing was written", output)
        self.assertNotIn("ABORT", output)
        self.assertEqual(pflash.writes(), [])
        self.assertUntouched()


@unittest.skipUnless(LIVE_PNOR and LIVE_KIT, "FIRESTONE_LIVE_PNOR and FIRESTONE_KIT are not both set")
class LiveFlowTest(FlowBase):
    """The flows on the private dump of compute-2 and the CI-cut kit."""

    @classmethod
    def provide(cls) -> tuple[Path, Path]:
        """Use the paths from the environment."""
        return Path(LIVE_KIT), Path(LIVE_PNOR)


if __name__ == "__main__":
    unittest.main()

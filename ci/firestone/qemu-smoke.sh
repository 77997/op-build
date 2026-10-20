#!/bin/bash
set -euo pipefail

usage() {
	cat >&2 <<-EOF
	usage: $0 [--timeout SECONDS] [--log FILE] SKIBOOT_LID ZIMAGE_EPAPR

	Boots SKIBOOT_LID (skiboot.lid, or skiboot.lid.xz which is
	decompressed first) and ZIMAGE_EPAPR (the skiroot kernel with its
	initramfs) on QEMU's powernv8 machine: a POWER8 v2.0 CPU, PHB3 host
	bridges and the machine's built-in ipmi-bmc-sim behind an IPMI BT
	interface, for which skiboot selects its "QEMU POWER8" platform with
	the same ast2400:ami BMC personality as Firestone.  The console log
	is scanned for petitboot's main menu ("Welcome to Petitboot" or the
	"Petitboot (vX.Y)" title).

	Exits 0 when the menu appears within --timeout seconds (default
	600).  Exits 1 on timeout, when QEMU exits first (a panic reboots
	and -no-reboot turns that into an exit), or as soon as the console
	shows a skiboot assert or fatal exception, a kernel oops or panic,
	or an illegal instruction, printing the tail of the console log.
	--log keeps the full console log at FILE; otherwise it lives in a
	temporary directory that is removed on exit.
	EOF
	exit 2
}

fail() {
	echo "error: $*" >&2
	exit 1
}

timeout_s=600
log=""
while [ $# -gt 0 ]; do
	case "$1" in
	--timeout)
		[ $# -ge 2 ] || usage
		timeout_s=$2
		shift 2
		;;
	--log)
		[ $# -ge 2 ] || usage
		log=$2
		shift 2
		;;
	-*)
		usage
		;;
	*)
		break
		;;
	esac
done

[ $# -eq 2 ] || usage
skiboot=$1
kernel=$2
case "${timeout_s}" in
"" | *[!0-9]*) usage ;;
esac
[ -f "${skiboot}" ] || fail "skiboot image not found: ${skiboot}"
[ -f "${kernel}" ] || fail "kernel image not found: ${kernel}"

qemu=qemu-system-ppc64
command -v "${qemu}" >/dev/null ||
	fail "${qemu} not found; on Ubuntu install the qemu-system-ppc package"
qemu_version=$("${qemu}" --version)
qemu_version=${qemu_version%%$'\n'*}
machines=$("${qemu}" -machine help)
grep -q '^powernv8 ' <<<"${machines}" ||
	fail "${qemu_version} has no powernv8 machine"
cpus=$("${qemu}" -machine powernv8 -cpu help)
grep -qw 'power8_v2.0' <<<"${cpus}" ||
	fail "${qemu_version} has no power8_v2.0 CPU model"

workdir=$(mktemp -d)
qemu_pid=""

cleanup() {
	if [ -n "${qemu_pid}" ] && kill -0 "${qemu_pid}" 2>/dev/null; then
		kill "${qemu_pid}" 2>/dev/null || true
		wait "${qemu_pid}" 2>/dev/null || true
	fi
	rm -rf "${workdir}"
}
trap cleanup EXIT

[ -n "${log}" ] || log="${workdir}/console.log"
: >"${log}"

case "${skiboot}" in
*.xz)
	xz -dc "${skiboot}" >"${workdir}/skiboot.lid"
	skiboot="${workdir}/skiboot.lid"
	;;
esac

esc=$'\033'

screen_text() {
	LC_ALL=C tr -d '\000' <"${log}" |
		LC_ALL=C sed -e "s/${esc}\[[0-9;?]*[A-Za-z]/ /g" \
			-e "s/${esc}[()][0-9A-Za-z]//g" \
			-e 's/[[:space:]][[:space:]]*/ /g'
}

show_tail() {
	echo "---- last 120 console lines (${log}) ----" >&2
	screen_text | tail -n 120 >&2
	if [ -s "${workdir}/qemu.stderr" ]; then
		echo "---- qemu stderr ----" >&2
		cat "${workdir}/qemu.stderr" >&2
	fi
}

echo "${qemu_version}"
echo "skiboot: ${skiboot} ($(($(wc -c <"${skiboot}"))) bytes)"
echo "kernel:  ${kernel} ($(($(wc -c <"${kernel}"))) bytes)"

"${qemu}" \
	-machine powernv8 \
	-cpu power8_v2.0 \
	-m 2G \
	-nographic \
	-monitor none \
	-serial "file:${log}" \
	-nic none \
	-no-reboot \
	-bios "${skiboot}" \
	-kernel "${kernel}" \
	</dev/null >"${workdir}/qemu.stdout" 2>"${workdir}/qemu.stderr" &
qemu_pid=$!

pass_re='Welcome to Petitboot|Petitboot \(v[0-9]'
fail_re='assert failed at|Fatal (System Reset|TRAP|Exception|MCE)|Machine Check Stop|Kernel panic|Oops: |Unable to handle kernel|Illegal instruction'

start=${SECONDS}
while :; do
	text=$(screen_text)
	if grep -Eq -- "${pass_re}" <<<"${text}"; then
		echo "PASS: petitboot menu reached after $((SECONDS - start)) s"
		grep -Eo -m 1 -- ".{0,40}(${pass_re}).{0,40}" <<<"${text}"
		exit 0
	fi
	if grep -Eq -- "${fail_re}" <<<"${text}"; then
		show_tail
		fail "console shows a fatal error: $(grep -Eo -m 1 -- "${fail_re}" <<<"${text}")"
	fi
	if ! kill -0 "${qemu_pid}" 2>/dev/null; then
		rc=0
		wait "${qemu_pid}" || rc=$?
		qemu_pid=""
		show_tail
		fail "QEMU exited with status ${rc} before petitboot appeared"
	fi
	if [ $((SECONDS - start)) -ge "${timeout_s}" ]; then
		show_tail
		fail "petitboot did not appear within ${timeout_s} s"
	fi
	sleep 2
done

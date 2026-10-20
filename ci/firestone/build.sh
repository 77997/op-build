#!/bin/bash
set -euo pipefail

usage() {
	cat >&2 <<-EOF
	usage: MAKE_TARGET=<targets> $0

	Builds firestone_defconfig inside the CI container, from the top of
	the op-build tree.  MAKE_TARGET must be set: empty runs the full
	build (hostboot-p8 first so that it fails fast, then everything,
	then legal-info); otherwise only the named buildroot targets are
	built after the defconfig and download steps.
	EOF
	exit 2
}

fail() {
	echo "error: $*" >&2
	exit 1
}

require_line() {
	grep -qxF -- "$2" "$1" || fail "$1 lacks the line: $2"
}

[ $# -eq 0 ] || usage
[ "${MAKE_TARGET+set}" = set ] || usage
[ -x ./op-build ] || usage
[ -f openpower/configs/firestone_defconfig ] || usage

ccache_dir="${PWD}/.ccache"

./op-build firestone_defconfig
ci/firestone/check-defconfig.sh openpower/configs/firestone_defconfig output/.config

buildroot/utils/config --file output/.config \
	--enable CCACHE \
	--set-str CCACHE_DIR "${ccache_dir}" \
	--set-str CCACHE_INITIAL_SETUP "--max-size=4G"
./op-build olddefconfig
require_line output/.config 'BR2_CCACHE=y'
require_line output/.config "BR2_CCACHE_DIR=\"${ccache_dir}\""

./op-build source

if [ -n "${MAKE_TARGET}" ]; then
	read -r -a targets <<< "${MAKE_TARGET}"
	./op-build "${targets[@]}"
	exit 0
fi

./op-build hostboot-p8
./op-build
./op-build legal-info

linux_configs=(output/build/linux-[0-9]*/.config)
[ "${#linux_configs[@]}" -eq 1 ] && [ -f "${linux_configs[0]}" ] ||
	fail "expected exactly one kernel build, found: ${linux_configs[*]}"
require_line "${linux_configs[0]}" 'CONFIG_TARGET_CPU="power8"'
if grep -E '^CONFIG_POWER(9|10)_CPU=y' "${linux_configs[0]}"; then
	fail "the skiroot kernel is built for a CPU newer than POWER8"
fi
while IFS= read -r line; do
	[ -n "${line}" ] || continue
	require_line "${linux_configs[0]}" "${line}"
done < openpower/configs/linux/skiroot-firestone.fragment

initramfs=$(xz -dc output/images/rootfs.cpio.xz | cpio -it --quiet)
for forbidden in 'lib/modules/.' 'lib/firmware/.' 'etc/udev/hwdb.bin'; do
	if grep -E "^(\./)?${forbidden}" <<< "${initramfs}"; then
		fail "the skiroot initramfs contains ${forbidden%/.}"
	fi
done

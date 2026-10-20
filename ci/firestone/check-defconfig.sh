#!/bin/bash
set -euo pipefail

usage() {
	cat >&2 <<-EOF
	usage: $0 DEFCONFIG DOTCONFIG

	Proves that every symbol assignment in DEFCONFIG survived into the
	DOTCONFIG that kconfig generated from it.  kconfig silently drops
	symbols it does not know and silently overrides values whose
	dependencies are not met, so a defconfig can stop meaning what it
	says without any build error.  Also asserts the POWER8 code
	generation the Firestone build depends on, and the Alternate
	Toolchain (GCC 6.5.0, compiler only, with binutils 2.31.1) that
	hostboot-p8 and occ-p8 are built with, including the values
	savedefconfig leaves out because they are the defaults.
	EOF
	exit 2
}

[ $# -eq 2 ] || usage
defconfig=$1
dotconfig=$2
[ -f "${defconfig}" ] || usage
[ -f "${dotconfig}" ] || usage

checked=0
drifted=0

report_drift() {
	local wanted=$1
	local symbol=$2
	local actual
	if ! actual=$(grep -E "^(# )?${symbol}[= ]" "${dotconfig}"); then
		actual="absent from ${dotconfig}"
	fi
	echo "DRIFT: ${wanted}  ->  ${actual}"
	drifted=$((drifted + 1))
}

while IFS= read -r line || [ -n "${line}" ]; do
	case "${line}" in
	BR2_*=*)
		symbol=${line%%=*}
		;;
	"# BR2_"*" is not set")
		symbol=${line#\# }
		symbol=${symbol%% *}
		;;
	"" | "#"*)
		continue
		;;
	*)
		echo "error: ${defconfig}: cannot parse line: ${line}" >&2
		exit 2
		;;
	esac
	checked=$((checked + 1))
	if ! grep -qxF -- "${line}" "${dotconfig}"; then
		report_drift "${line}" "${symbol}"
	fi
done < "${defconfig}"

for required in \
	'BR2_powerpc64le=y' \
	'BR2_powerpc_power8=y' \
	'BR2_GCC_TARGET_CPU="power8"' \
	'BR2_PACKAGE_ALTERNATE_GCC=y' \
	'BR2_ALTERNATE_GCC_VERSION="6.5.0"' \
	'BR2_ALTERNATE_GCC_COMPILER_ONLY=y' \
	'BR2_PACKAGE_ALTERNATE_BINUTILS=y' \
	'BR2_ALTERNATE_BINUTILS_VERSION="2.31.1"'; do
	if grep -qxF -- "${required}" "${defconfig}"; then
		continue
	fi
	checked=$((checked + 1))
	if ! grep -qxF -- "${required}" "${dotconfig}"; then
		report_drift "${required}" "${required%%=*}"
	fi
done

echo "defconfig drift check: ${checked} assignments checked, ${drifted} drifted"
[ "${drifted}" -eq 0 ]

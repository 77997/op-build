#!/bin/bash
set -euo pipefail

usage() {
	cat >&2 <<-EOF
	usage: $0 OUTDIR

	Gathers the logs and the small build outputs of a firestone build
	from the top of the op-build tree into OUTDIR, for upload as CI
	artefacts.  It runs after failed builds too, so every input is
	optional; whatever was not produced is listed instead of copied.
	output/images and output/legal-info are uploaded in place.
	EOF
	exit 2
}

[ $# -eq 1 ] || usage
out=$1

mkdir -p "${out}/logs" "${out}/pnor" "${out}/hostboot/generated"

copy() {
	local src
	local dst=${!#}
	for src in "${@:1:$#-1}"; do
		if [ -e "${src}" ]; then
			cp -a -L "${src}" "${dst}"
		else
			echo "not produced: ${src}"
		fi
	done
}

copy build.log "${out}/logs/"
copy output/build/build-time.log "${out}/logs/"
copy output/.config "${out}/logs/buildroot.config"
copy output/build/linux-[0-9]*/.config "${out}/logs/linux.config"

staging=output/host/powerpc64le-buildroot-linux-gnu/sysroot
copy "${staging}/openpower_pnor_scratch" "${out}/pnor/"
copy "${staging}/openpower_version" "${out}/pnor/"
copy "${staging}/openpower_mrw_scratch" "${out}/pnor/"

copy "${staging}/hostboot_build_images" "${out}/hostboot/"
copy output/build/hostboot-p8-*/src/usr/devtree/bld_devtree.C "${out}/hostboot/"
copy output/build/hostboot-p8-*/img/*.if output/build/hostboot-p8-*/img/*.prf \
	"${out}/hostboot/generated/"
copy output/build/hostboot-p8-*/obj/genfiles "${out}/hostboot/generated/"

{
	echo "== disk"
	df -h .
	echo
	echo "== tree sizes"
	for dir in dl .ccache output/build output/host output/images output/legal-info; do
		if [ -d "${dir}" ]; then
			du -sh "${dir}"
		fi
	done
	echo
	echo "== output/images"
	if [ -d output/images ]; then
		ls -l output/images
	fi
	echo
	echo "== skiroot"
	for file in output/images/zImage.epapr output/images/rootfs.cpio.xz output/build/linux-[0-9]*/vmlinux; do
		if [ -f "${file}" ]; then
			stat --format '%s %n' "${file}"
		fi
	done
	if [ -f output/images/rootfs.cpio.xz ]; then
		echo
		echo "== initramfs, 20 largest files"
		xz -dc output/images/rootfs.cpio.xz | cpio -itv --quiet | sort -k5 -n -r | sed -n '1,20p'
	fi
	echo
	echo "== ccache"
	if [ -x output/host/bin/ccache ]; then
		BR_CACHE_DIR="${PWD}/.ccache" output/host/bin/ccache -s
	fi
} > "${out}/logs/sizes.txt"
cat "${out}/logs/sizes.txt"

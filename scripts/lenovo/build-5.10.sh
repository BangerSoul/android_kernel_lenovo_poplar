#!/usr/bin/env bash
# Build Lenovo's published 5.10.198 kernel for TB311FU (poplar).
#
#   scripts/lenovo/build-5.10.sh [srctree]
#
# Expects the Lenovo package extracted into the current directory:
#   kernel-5.10/            from kernel_5.10.tar
#   build/kernel_config/    from the package root
#
# Output: ./out/arch/arm64/boot/Image.gz and ./out/modules.tar.gz
set -euo pipefail

SRC=${1:-kernel-5.10}
ROOT=$PWD
OUT=$ROOT/out
BOARD_CFG=tb8786p1_64_k510_wifi_row_defconfig
MERGED=build/kernel_config/$BOARD_CFG
IN_TREE=$SRC/arch/arm64/configs/$BOARD_CFG

[ -d "$SRC" ] || { echo "error: no kernel tree at $SRC" >&2; exit 1; }

# The in-tree board config is only a 343-line FRAGMENT with no CONFIG_MODULES
# at all; applying it alone fails at the modules target. Lenovo's merged
# config lives in build/kernel_config (7,875 lines, CONFIG_MODULES=y) and is
# what their kernel_build.sh actually uses.
#
# Note: passing two defconfig targets to make does NOT merge them - each one
# rewrites .config from scratch - so the merged file is the only sane input.
if [ -f "$MERGED" ]; then
  mkdir -p "$(dirname "$IN_TREE")"
  cp "$MERGED" "$IN_TREE"
  echo "using Lenovo's merged config: $MERGED"
elif [ ! -f "$IN_TREE" ]; then
  echo "error: neither $MERGED nor $IN_TREE exists" >&2
  exit 1
else
  echo "warning: $MERGED missing, using the in-tree fragment (may have no CONFIG_MODULES)"
fi

# O= is resolved inside the source tree because of -C, so pass an absolute path.
#
# CROSS_COMPILE is not optional with LLVM=1: it is what gives clang its
# --target triple. Without it clang stays on x86_64 and dies on the first
# arm64 inline asm with "unknown register name 'x0'".
export ARCH=arm64
export LLVM=1 LLVM_IAS=1
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_COMPAT=arm-linux-gnueabi-

# Lenovo built this tree with clang-r416183b, which never emitted several
# diagnostics that clang 14 does. The MTK makefiles pass -Werror, so those new
# warnings become hard errors in code we have no reason to touch. Demote only
# the noisy classes back to warnings; KCFLAGS is appended after -Werror, so it
# wins. This is a compiler-compatibility shim, not a correctness change.
export KCFLAGS="-Wno-error=unused-but-set-variable -Wno-error=unused-variable \
-Wno-error=unused-function -Wno-error=unused-value -Wno-error=implicit-fallthrough \
-Wno-error=misleading-indentation -Wno-error=address-of-packed-member \
-Wno-error=tautological-compare -Wno-error=missing-prototypes \
-Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types \
-Wno-error=int-conversion -Wno-error=enum-conversion -Wno-error=uninitialized \
-Wno-error=sometimes-uninitialized -Wno-error=format -Wno-error=constant-conversion"

echo "== config: $BOARD_CFG =="
make -C "$SRC" O="$OUT" "$BOARD_CFG"

if ! grep -q '^CONFIG_MODULES=y' "$OUT/.config"; then
  echo "error: CONFIG_MODULES is not enabled in $OUT/.config" >&2
  exit 1
fi
echo "config OK: CONFIG_MODULES=y"

echo "== build: Image.gz + modules (-j${JOBS:-$(nproc)}) =="
make -C "$SRC" O="$OUT" -j"${JOBS:-$(nproc)}" Image.gz modules

echo "== modules_install =="
make -C "$SRC" O="$OUT" INSTALL_MOD_PATH="$ROOT/modules-root" modules_install
tar czf "$OUT/modules.tar.gz" -C "$ROOT/modules-root" lib/modules

echo "== artifacts =="
ls -l "$OUT/arch/arm64/boot/Image.gz" "$OUT/modules.tar.gz"
echo "Image.gz sha256: $(sha256sum "$OUT/arch/arm64/boot/Image.gz" | awk '{print $1}')"

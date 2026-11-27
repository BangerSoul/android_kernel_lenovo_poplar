# Lenovo TB311FU kernel source drop — ZUI 16.0.10.033 (Linux 5.10.198)

Provenance record for the kernel sources Lenovo publishes for the Lenovo Tab
TB311FU (`poplar`, MT8786 / mt6768).

## The package

| | |
|---|---|
| File | `lenovo_tab_(tb311fu)_opensource_zui_16.0.10.033_stable_version.tgz` |
| URL | https://download.lenovo.com/consumer/mobiles/lenovo_tab_%28tb311fu%29_opensource_zui_16.0.10.033_stable_version.tgz |
| Size | 758,895,617 bytes (724 MiB), published 2025-09-26 |
| sha256 | `95987a05be184b719420008542f3d2ce65eac82b181f1e6f052422d740fd272c` |
| Kernel | Linux **5.10.198**, 92,516 files inside `kernel_5.10.tar` |
| Board | `tb8786p1_64_k510_wifi_row` |
| Toolchain | `LLVM=1 LLVM_IAS=1`, `CROSS_COMPILE=aarch64-linux-gnu-` |

Rest of the drop, for reference: `kernel_5.10.tar` is 720 MB of the 724;
`libcore/ojluni` 2,391 files, `external/` 843, `bionic/` 58,
`art/openjdkjvmti` 51, `vendor/mediatek` 113 (makefiles and metadata — no
blobs), `system/memory` 23.

## What is committed here

`source-notes/lenovo-zui_16.0.10.033/`
- `lenovo-readme.txt`, `lenovo-kernel_build.sh` — Lenovo's own build entry point
- `tb8786p1_64_k510_wifi_row_defconfig` — the WiFi ROW board config this device ships
- `kernel-version.txt` — 5.10.198

`drivers/misc/mediatek/widevine_drm/`
- `widevine_driver.c` (236 lines), `widevine_driver.h` (31), `Kconfig`, `Makefile`
- unmodified from `kernel-5.10/drivers/misc/mediatek/widevine_drm/`,
  GPL-2.0, Copyright (C) 2019-2021 MediaTek Inc.
- `CONFIG_MTK_WIDEVINE_DRM=m`; the Makefile adds
  `-I$(srctree)/drivers/dma-buf/heaps`, and the driver includes `mtk_heap.h`

The driver sits at its natural kernel path so it can be dropped into a 6.6
tree for a port; everything else is documentation and config, so diffs stay
readable.

## The limitation of this drop

This is the **5.10.198** branch. The tablet on current firmware
(ZUI 17.5.36.508) runs a **6.6.82 GKI** kernel, and Lenovo has published no
6.6 source for TB311FU. Siblings on the same
`6.6.82-android15-8-g076ac12bde16-ab13715361-4k` build (TB305FU, TB336FU) have
open requests in `github.com/lenovo/gplcc` for exactly this reason.

So this drop cannot produce a `widevine_driver.ko` that loads on the current
kernel. It is the reference for porting that driver to 6.6 — the only route to
a module matching a 6.6 kernel short of MediaTek publishing theirs.

## Deliberately not included

No 6.6 GKI tree, no 6.6 vendor modules, no `vendor_dlkm` image and no
`modules.load` exist in Lenovo's package. The device tree and vendor tree need
nothing from this drop: a vendor tree carries blobs plus
`proprietary-files.txt`, and the only Widevine blob here is the 5.10 one,
which does not belong in a 6.6 ROM.

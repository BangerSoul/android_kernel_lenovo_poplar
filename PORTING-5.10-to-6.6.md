# Porting Lenovo's 5.10.198 tree to 6.6 — measured scope

What this repository has and what "upstreaming it to latest" actually costs.

## What Lenovo published

`lenovo_tab_(tb311fu)_opensource_zui_16.0.10.033_stable_version.tgz`,
sha256 `95987a05…fd272c`, 724 MiB, containing `kernel_5.10.tar`:
Linux **5.10.198**, 92,516 files, **2.62 GB** uncompressed.

MediaTek-specific content:

| Subtree | Files |
|---|---|
| `drivers/misc/mediatek/` | 5,004 |
| `sound/soc/mediatek/` | 349 |
| `drivers/clk/mediatek/` | 304 |
| `drivers/gpu/drm/mediatek/` | 230 |
| `arch/arm64/boot/dts/mediatek/` | 192 |
| **total vendor surface** | **6,079** |

## Why this is a BSP port, not a rebase

A rebase replays a small delta. Here the delta *is* the product: 6,079 files
against kernel APIs that moved across five major releases. Representative
breakage already confirmed against v6.6:

- `class_create(THIS_MODULE, name)` -> `class_create(name)` (changed in 6.4).
  `widevine_drm` uses the old form and will not compile.
- Named-variadic macros (`args...`) are rejected; kernel wants `...`/`__VA_ARGS__`.
- `snd_soc_*` and clk frameworks changed repeatedly between 5.15 and 6.6.
- dma-buf / dma-heap internals moved; MTK's `mtk_heap.h` secure-handle API
  has no upstream counterpart at all (mainline `drivers/dma-buf/heaps/` is
  only `cma_heap.c` + `system_heap.c`, in v6.6 through v6.15).

SoC vendors spend roughly a year per generation doing exactly this work.

## The architectural blocker, which matters more

TB311FU is a **GKI 2.0** device on `android15-6.6`. Its 6.6 kernel image
contains **no** `drivers/misc/mediatek` — that code ships as separate modules
in `vendor_dlkm`, built against the frozen GKI KMI. The vendor tree confirms
it: `vendor_dlkm/lib/modules/*.ko` plus `vendor/apex/*`.

Consequence: merging this in-tree MTK code into a 6.6 GKI kernel does not
produce a kernel the tablet can boot. The ROM's vendor modules, DT and
`vendor_boot` are built for the GKI ABI, and a competing in-tree driver set
would both duplicate and conflict with them.

## What is worth doing, in order

1. **Build the published tree as-is** — `.github/workflows/build-lenovo-5.10.yml`
   produces `Image.gz` and every module from Lenovo's own config. Cheap, and it
   proves the source and config are complete.
2. **Port individual vendors to 6.6, not the tree** — `widevine_drm` is 267
   lines and its whole delta is known. That is on
   this branch and is the piece with actual value for
   Widevine L1.
3. **Full 6.6 vendor port** — needs MediaTek's 6.6 vendor module tree, which
   is not public. This is why TB305FU/TB336FU have open GPL requests in
   `github.com/lenovo/gplcc` for the same 6.6.82 build.

## Not attempted here

No attempt is made to make the 5.10 tree build against a 6.6 base. Doing so
without the vendor's 6.6 sources would produce a non-booting image and weeks
of API churn, and it would still be the wrong architecture for a GKI device.

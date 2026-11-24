# Lenovo Tab (TB311FU / poplar) - Linux 6.6 Kernel Compilation & Boot Tooling Guide

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
[![Device: Lenovo TB311FU](https://img.shields.io/badge/Device-Lenovo%20TB311FU%20(poplar)-orange.svg)](https://www.lenovo.com)
[![Kernel: Linux 6.6 GKI 2.0](https://img.shields.io/badge/Kernel-Linux%206.6%20GKI%202.0-teal.svg)](https://kernel.org)
[![Toolchain: Clang 18](https://img.shields.io/badge/Toolchain-AOSP%20Clang%2018.0.0%20(r510928)-purple.svg)](https://android.googlesource.com)

This guide provides complete, production-grade instructions for configuring, patching, building, and assembling the **Linux 6.6 LTS Generic Kernel Image (GKI 2.0)** for the **Lenovo Tab** (Model: `TB311FU`, internal codename `poplar` / `poplar_row_wifi`, MediaTek MT8786 / Helio G85).

---

## Table of Contents
1. [Architecture & Hardware Overview](#1-architecture--hardware-overview)
2. [Toolchain & Build Environment Prerequisites](#2-toolchain--build-environment-prerequisites)
3. [Source Code Acquisition](#3-source-code-acquisition)
4. [Hardware Patches](#4-hardware-patches)
   - [4.1 Backlight Floor Clamp (>= 48)](#41-backlight-floor-clamp--48)
   - [4.2 Wi-Fi RFKILL Symbol Export](#42-wi-fi-rfkill-symbol-export)
5. [Kernel Configuration (Defconfig)](#5-kernel-configuration-defconfig)
6. [Kernel Compilation Workflow](#6-kernel-compilation-workflow)
   - [Method A: Standalone Make with Clang 18](#method-a-standalone-make-with-clang-18)
   - [Method B: Google Kleaf / Bazel Build](#method-b-google-kleaf--bazel-build)
7. [Out-of-Tree Wi-Fi Module Compilation (`wlan_drv_gen4m_6768.ko`)](#7-out-of-tree-wi-fi-module-compilation-wlan_drv_gen4m_6768ko)
8. [Little Kernel (LK) AVB 2.0 Boot Vector Assembly](#8-little-kernel-lk-avb-20-boot-vector-assembly)
   - [8.1 The LK Invariant Explained](#81-the-lk-invariant-explained)
   - [8.2 Boot Vector Assembly Tool CLI](#82-boot-vector-assembly-tool-cli)
   - [8.3 Unpacking Existing Boot Images](#83-unpacking-existing-boot-images)
   - [8.4 Cryptographic AVB Invariant Verification](#84-cryptographic-avb-invariant-verification)
9. [Flashing & Runtime Verification](#9-flashing--runtime-verification)
10. [Repository & GitHub Publishing](#10-repository--github-publishing)

---

## 1. Architecture & Hardware Overview

| Parameter | Specification | Details / Verification Source |
|---|---|---|
| **Device Model** | Lenovo TB311FU | Lenovo Tab (`ro.config.lgsi.market_name=Lenovo Tab`, `mssi_t_64_cn_armv82_wifi`) |
| **Internal Codename** | `poplar` / `poplar_row_wifi` | MTK Board: `tb8786p1_64_k66` / Base Project `tc422` |
| **SoC** | MediaTek MT8786 / Helio G85 | 2x ARM Cortex-A75 @ 2.0 GHz + 6x ARM Cortex-A55 @ 1.8 GHz |
| **GPU** | ARM Mali-G52 2EEMC2 | Bifrost v7 architecture, Panfrost open-source driver compatible |
| **Userspace & ABI** | Pure 64-bit (`arm64-v8a`) | 64-bit Android Binder IPC (`CONFIG_ANDROID_BINDER_IPC_32BIT` NOT set) |
| **Kernel Baseline** | Linux 6.6 LTS GKI 2.0 | Stock release: `6.6.82-android15-8-g076ac12bde16-ab13715361-4k` |
| **Page Size** | 4096 bytes (4 KB) | `CONFIG_ARM64_4K_PAGES=y` |
| **Boot Header** | Android Boot Header v4 | `boot.img` 32 MiB, `init_boot.img` 8 MiB, `vendor_boot.img` 64 MiB |
| **AVB Requirement** | AVB 2.0 Chained Invariant | VBMeta Offset == `0xDE3000` (14,561,280 bytes), total 33,554,432 bytes |

---

## 2. Toolchain & Build Environment Prerequisites

Compilation should be performed on an **Ubuntu 22.04 LTS or 24.04 LTS** (x86_64) host.

### 2.1 Host Packages
Install required build dependencies:
```bash
sudo apt update && sudo apt install -y \
    build-essential \
    libssl-dev \
    bc \
    bison \
    flex \
    libncurses-dev \
    libelf-dev \
    libfl-dev \
    lz4 \
    gzip \
    python3 \
    git \
    curl \
    rsync \
    kmod
```

### 2.2 Google Clang 18 Toolchain (`r510928`)
Stock TB311FU GKI kernels are compiled with Android Clang 18.0.0 (`r510928`, LLVM 18.0.0). Download the matching prebuilt toolchain:
```bash
mkdir -p ~/toolchains/clang-r510928
cd ~/toolchains/clang-r510928
curl -LO https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/main/clang-r510928.tar.gz
tar -xzf clang-r510928.tar.gz
rm clang-r510928.tar.gz
```

Verify toolchain:
```bash
~/toolchains/clang-r510928/bin/clang --version
# Output: Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928) clang version 18.0.0
```

---

## 3. Source Code Acquisition

You can acquire downstream kernel source through either the official Lenovo GPL open-source portal or the community reference repository:

### Option A: Official Lenovo Open Source GPL Portal
Lenovo publishes the full GPL release archive for TB311FU:
- **Archive URL**: `https://download.lenovo.com/consumer/mobiles/lenovo_tab_(tb311fu)_opensource_zui_16.0.10.033_stable_version.tgz`
- **Archive Size**: ~758.89 MB (HTTP 200 OK verified)

Download and extract:
```bash
wget https://download.lenovo.com/consumer/mobiles/lenovo_tab_\(tb311fu\)_opensource_zui_16.0.10.033_stable_version.tgz
tar -xzf lenovo_tab_\(tb311fu\)_opensource_zui_16.0.10.033_stable_version.tgz
cd kernel-6.6
```

### Option B: Community Reference Repository
```bash
git clone https://github.com/arthurpatrociniofernandes9-ai/kernel_lenovo_TB311FU.git -b main
cd kernel_lenovo_TB311FU
```

---

## 4. Hardware Patches

### 4.1 Backlight Floor Clamp (>= 48)
- **Patch file**: `patches/0001-backlight-floor-clamp-48.patch`
- **Root Cause**: On TB311FU, the 10.1" 1920x1200 WUXGA IPS LCD panel backlight boost converter drops out of regulation and shuts off whenever the raw PWM duty cycle drops below 48 (approx 1.17% on 12-bit $0 \dots 4095$ scale). When the user drags the brightness slider to minimum (0% or 1%), the screen drops to 0 nits (complete black screen), making the tablet appear frozen or dead.
- **Solution**: Clamp brightness in `drivers/video/backlight/backlight.c` and `drivers/video/backlight/pwm_bl.c` so that active panel brightness (`brightness > 0`) is clamped to `>= 48`, while preserving `brightness == 0` for screen blanking / suspend.

Apply patch:
```bash
patch -p1 < patches/0001-backlight-floor-clamp-48.patch
```

### 4.2 Wi-Fi RFKILL Symbol Export
- **Patch file**: `patches/0002-wifi-rfkill-export.patch`
- **Root Cause**: The MediaTek proprietary Wi-Fi driver `wlan_drv_gen4m_6768.ko` (in `vendor_dlkm`) depends on `rfkill_set_states()` to simultaneously synchronize hardware and software radio block states. In standard Android GKI 6.6 builds, unlisted symbols are stripped via `CONFIG_TRIM_UNUSED_KSYMS=y`.
- **Solution**: Explicitly export `rfkill_set_states` in `net/rfkill/core.c` via `EXPORT_SYMBOL(rfkill_set_states)` and add `rfkill_set_states` to `android/abi_gki_aarch64`.

Apply patch:
```bash
patch -p1 < patches/0002-wifi-rfkill-export.patch
```

---

## 5. Kernel Configuration (Defconfig)

The verified board configuration is located at `arch/arm64/configs/tb311fu_defconfig` (and mirrored at the repository root `tb311fu_defconfig`).

Copy the board configuration into place:
```bash
cp tb311fu_defconfig arch/arm64/configs/tb311fu_defconfig
```

### Categorized Symbol Inventory

| Category | Config Symbol | Value | Reason |
|---|---|---|---|
| **Architecture** | `CONFIG_ARM64` | `y` | 64-bit ARM architecture |
| **Page Geometry** | `CONFIG_ARM64_4K_PAGES` | `y` | 4KB Page size matching Android GKI 2.0 |
| **Page Geometry** | `CONFIG_ARM64_PAGE_SHIFT` | `12` | 12-bit page shift (4096 bytes) |
| **Android IPC** | `CONFIG_ANDROID_BINDER_IPC` | `y` | Android Binder IPC subsystem |
| **Android IPC** | `CONFIG_ANDROID_BINDERFS` | `y` | Binder filesystem (`/dev/binderfs`) |
| **Android IPC** | `CONFIG_ANDROID_BINDER_DEVICES` | `"binder,hwbinder,vndbinder"` | Standard device nodes |
| **Android IPC** | `CONFIG_ANDROID_BINDER_IPC_32BIT` | `n` (not set) | Pure 64-bit userspace compatibility |
| **Modules** | `CONFIG_MODULES` | `y` | Dynamic loadable kernel module support |
| **Connectivity** | `CONFIG_RFKILL` | `m` | Loadable module matching `system_dlkm` layout |
| **Connectivity** | `CONFIG_CRYPTO_LIB_ARC4` | `m` | Required cryptographic helper for WEP/TKIP |
| **Platform** | `CONFIG_ARCH_MEDIATEK` | `y` | MediaTek SoC family enablement |
| **Platform** | `CONFIG_MTK_PLATFORM` | `"mt6768"` | Helio G85 platform identifier |
| **Platform** | `CONFIG_ARM_MEDIATEK_CPUFREQ` | `y` | MediaTek DVFS CPU frequency scaling |
| **Graphics** | `CONFIG_DRM_PANFROST` | `m` | Open-source ARM Mali Bifrost GPU driver |
| **Audio** | `CONFIG_SND_SOC_MT6358` | `m` | PMIC audio codec |
| **Audio** | `CONFIG_SND_SOC_MT6768_AFE` | `m` | MediaTek Audio Front End driver |
| **Audio** | `CONFIG_SND_SOC_AW883XX` | `m` | Awinic Smart PA dual stereo speaker amplifier |
| **Filesystems** | `CONFIG_EROFS_FS` | `y` | High-efficiency read-only super partition mounting |
| **Integrity** | `CONFIG_DM_VERITY` | `y` | Device mapper verity integrity checking |

---

## 6. Kernel Compilation Workflow

### Method A: Standalone Make with Clang 18

Set up environment variables pointing to Clang 18:
```bash
export ARCH=arm64
export SUBARCH=arm64
export CC=clang
export CLANG_TRIPLE=aarch64-linux-gnu-
export CROSS_COMPILE=aarch64-linux-android-
export PATH="$HOME/toolchains/clang-r510928/bin:$PATH"
export LLVM=1
export LLVM_IAS=1
```

#### Step 1: Load Defconfig
```bash
make tb311fu_defconfig
```

#### Step 2: Compile Kernel Image and Modules
```bash
make -j$(nproc) Image.gz modules
```

The compiled kernel image will be generated at:
`arch/arm64/boot/Image.gz` (or `arch/arm64/boot/Image`)

---

### Method B: Google Kleaf / Bazel Build

If building within an AOSP Generic Kernel Image (GKI) workspace:
```bash
repo init -u https://android.googlesource.com/kernel/manifest -b common-android15-6.6
repo sync -j$(nproc)

# Apply patches to common/
cd common
patch -p1 < /path/to/patches/0001-backlight-floor-clamp-48.patch
patch -p1 < /path/to/patches/0002-wifi-rfkill-export.patch
cd ..

# Build GKI kernel
tools/bazel build //common:kernel_aarch64
```

---

## 7. Out-of-Tree Wi-Fi Module Compilation (`wlan_drv_gen4m_6768.ko`)

MediaTek Wi-Fi requires building `wlan_drv_gen4m_6768.ko` against the compiled kernel tree:

```bash
cd vendor/mediatek/kernel_modules/connectivity/wlan/gen4m

make -C /path/to/kernel-6.6 M=$(pwd) \
    ARCH=arm64 \
    CC=clang \
    LLVM=1 \
    CROSS_COMPILE=aarch64-linux-android- \
    CONFIG_MTK_WLAN_SERVICE=m \
    modules
```

### Module Insertion Sequence at Boot
Because `wlan_drv_gen4m_6768.ko` depends on `cfg80211` and `rfkill`, modules must be loaded in strict dependency order:
```bash
insmod /vendor_dlkm/lib/modules/rfkill.ko
insmod /vendor_dlkm/lib/modules/libarc4.ko
insmod /vendor_dlkm/lib/modules/cfg80211.ko
insmod /vendor_dlkm/lib/modules/mac80211.ko
insmod /vendor_dlkm/lib/modules/wlan_drv_gen4m_6768.ko
```

---

## 8. Little Kernel (LK) AVB 2.0 Boot Vector Assembly

### 8.1 The LK Invariant Explained
On Lenovo MediaTek tablets (Helio G85 / MT8786), the Little Kernel (LK) bootloader strictly enforces an AVB 2.0 structural invariant:
$$\text{VBMeta Offset} == \text{HashDescriptor.image\_size} == 14,561,280\text{ bytes (0xDE3000)}$$

- The total `boot.img` size must strictly equal **33,554,432 bytes (32 MiB)**.
- Page 0 (0..4095 bytes) contains the Android Boot Header v4.
- Kernel payload starts at offset 4096.
- The region between the end of kernel payload and offset `14,561,280` (`0xDE3000`) must be zero-padded.
- The pristine 2,432-byte OEM RSA4096 VBMeta block must reside at offset `14,561,280`.
- The region between `14,563,712` and `33,554,368` must be zero-padded.
- The 64-byte AVB footer at offset `33,554,368` (`0x1FFFFC0`) must point to `vbmeta_offset = 14561280` and `original_image_size = 14561280`.

**Consequence of Violation:** If `boot.img` is assembled with standard `mkbootimg` without pinning VBMeta to `0xDE3000`, LK displays the Orange State warning and hardware power-cycles the tablet after exactly **2 seconds**, causing an infinite bootloop.

---

### 8.2 Boot Vector Assembly Tool CLI
Execute `tools/assemble_boot_vector.py` to assemble a verified boot vector:

```bash
python3 tools/assemble_boot_vector.py \
    --kernel arch/arm64/boot/Image.gz \
    --output boot.img
```

*Note*: If `--stock-boot` is not supplied, the tool automatically uses its embedded, cryptographically verified 2,432-byte Lenovo OEM RSA4096 VBMeta block.

#### Diagnostic Output:
```
==================================================================
 [BOOT VECTOR] Lenovo TB311FU Android Boot Header v4 Assembler
==================================================================
  [1/6] Ingested kernel payload:  14,538,864 bytes (13.87 MB)
  [3/6] Boot Header v4 constructed: 4,096 bytes (pagesize 4096, v4, cmdline set)
  [4/6] Pristine OEM VBMeta block: 2,432 bytes (flags=0x00, OEM key validated)
  [5/6] Zero-padding region:      18,320 bytes (offset 14,542,960 -> 14,561,280)
        LK AVB Invariant:         Offset (14,561,280) == HashDesc.image_size (14,561,280)
  [6/6] AVB footer injected:      offset 0x1ffffc0 (33,554,368 B)
------------------------------------------------------------------
 [SUCCESS] Boot vector assembled successfully: boot.img
           File Size: 33,554,432 bytes (32.0 MB)
           SHA-256:   ...
==================================================================
```

---

### 8.3 Unpacking Existing Boot Images
To unpack a stock or custom boot image into constituent components:
```bash
python3 tools/assemble_boot_vector.py --unpack boot.img --out-dir unpacked_boot/
```

This extracts:
- `unpacked_boot/kernel.gz`: Kernel payload
- `unpacked_boot/ramdisk.img`: Userspace ramdisk (if present)
- `unpacked_boot/vbmeta.bin`: 2,432-byte OEM VBMeta block
- `unpacked_boot/avb_footer.bin`: 64-byte AVB footer
- `unpacked_boot/boot_info.json`: Detailed metadata dump

---

### 8.4 Cryptographic AVB Invariant Verification
To perform a complete cryptographic audit of any boot image:
```bash
python3 tools/assemble_boot_vector.py --verify boot.img
```

This validates:
1. File size is strictly 33,554,432 bytes.
2. Boot Header v4 integrity.
3. AVB footer parameters.
4. 4096-byte page alignment of VBMeta block.
5. VBMeta flags byte 123 is `0x00` (verity intact).
6. OEM RSA4096 public key SHA-1 matches `8fcb864f11f53ed11284615fb67685522085d3a2`.
7. Auth block self-integrity SHA-256 matches `cdb31fa8398a68b4492fbcaaaa01732a8e7101cc3816326aa9ee980234226e9b`.
8. RSA4096 signature SHA-256 matches `fe45c90d220fbd0a32b14f74b86bad89757eb5ffebf6a25dcef843925ee57088`.
9. HashDescriptor image size strictly matches VBMeta offset (`14,561,280`).
10. Slack zero padding is clean.
11. AVB properties (`os_version`, `fingerprint`, `security_patch`) are parsed and confirmed.

---

## 9. Flashing & Runtime Verification

### 9.1 Bootloader Unlock Verification
Verify bootloader is unlocked (`ro.boot.flash.locked=0`, `ro.boot.verifiedbootstate=orange`):
```bash
fastboot getvar unlocked
```

### 9.2 Flashing `boot.img`
Flash the assembled 32 MiB boot image to slot A:
```bash
fastboot flash boot_a boot.img
fastboot reboot
```

### 9.3 Expected Behavior
- Tablet turns on and displays the standard 5-second Orange State notice:
  `Orange State - Your device has been unlocked and can't be trusted.`
- LK verifies `VBMeta Offset == 14,561,280` and proceeds immediately to kernel execution.
- No 2-second reboot loop occurs.
- Kernel boots into Android 14 / LineageOS userspace.
- Brightness slider at 0% maintains panel illumination (no 0-nit black screen).
- Wi-Fi toggle functions cleanly with `wlan_drv_gen4m_6768.ko`.

---

## 10. Repository & GitHub Publishing

- **Repository**: [`BangerSoul/android_kernel_lenovo_poplar`](https://github.com/BangerSoul/android_kernel_lenovo_poplar)
- **Remote (`origin`)**: `https://github.com/BangerSoul/android_kernel_lenovo_poplar.git`
- **Default / Target Branch**: `lineage-21.0`
- **Manifest Path**: `kernel/lenovo/poplar` (wired via [`BangerSoul/local_manifests_poplar`](https://github.com/BangerSoul/local_manifests_poplar) in `.repo/local_manifests/poplar.xml`)

### Related Repositories

| Component | Repository | Manifest / Workspace Path |
|---|---|---|
| **Project Hub & Research** | [`BangerSoul/ArrowOS-TB311FU`](https://github.com/BangerSoul/ArrowOS-TB311FU) | `/` |
| **Device Tree** | [`BangerSoul/android_device_lenovo_poplar`](https://github.com/BangerSoul/android_device_lenovo_poplar) | `device/lenovo/poplar` |
| **Proprietary Vendor Blobs** | [`BangerSoul/proprietary_vendor_lenovo_poplar`](https://github.com/BangerSoul/proprietary_vendor_lenovo_poplar) | `vendor/lenovo/poplar` |
| **Kernel Config & Boot Tooling** | [`BangerSoul/android_kernel_lenovo_poplar`](https://github.com/BangerSoul/android_kernel_lenovo_poplar) | `kernel/lenovo/poplar` |
| **Local Manifests** | [`BangerSoul/local_manifests_poplar`](https://github.com/BangerSoul/local_manifests_poplar) | `.repo/local_manifests` |

```bash
git clone https://github.com/BangerSoul/android_kernel_lenovo_poplar.git -b lineage-21.0
git remote -v
git push -u origin lineage-21.0
```


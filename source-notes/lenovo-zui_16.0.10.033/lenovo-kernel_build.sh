#!/bin/bash

rm -rf out/

# 获取脚本的绝对路径
script_path=$(realpath "$0")
# 获取脚本所在的目录
script_dir=$(dirname "$script_path")

##############################################
# set by user
##############################################
export KBUILD_VERBOSE=0
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_COMPAT=arm-linux-gnueabi-
export LLVM=1
export LLVM_IAS=1
LCT_KTOP=${script_dir}
LCT_PREBUILTS_TOOLS_PATH=${LCT_KTOP}
LCT_KERNEL_CLANG_ROOT=${LCT_PREBUILTS_TOOLS_PATH}/prebuilts/clang/host/linux-x86/clang-r416183b
LCT_KERNEL_SRC=${LCT_KTOP}/kernel-5.10
LCT_KERNEL_OUT=${LCT_KTOP}/out
LCT_KERNEL_JOBS=$(nproc)
#LCT_KERNEL_DEFCONFIG="gki_defconfig tb8786p1_64_k510_wifi_row_defconfig userdebug.config"
#LCT_KERNEL_DEFCONFIG="gki_defconfig tb8786p1_64_k510_wifi_prc_defconfig userdebug.config"
#LCT_KERNEL_DEFCONFIG="gki_defconfig tb8786p1_64_k510_row_defconfig userdebug.config"
#LCT_KERNEL_DEFCONFIG="gki_defconfig tb8786p1_64_k510_prc_defconfig userdebug.config"
LCT_KERNEL_DEFCONFIG="../../../../build/kernel_config/tb8786p1_64_k510_wifi_row_defconfig"
LCT_KERNEL_BUILD_CONF_ARGS=""
#LCT_KERNEL_BUILD_ALL_ARGS="Image.gz"
LCT_KERNEL_BUILD_ALL_ARGS="all"
##############################################


source build/build_kernel.sh


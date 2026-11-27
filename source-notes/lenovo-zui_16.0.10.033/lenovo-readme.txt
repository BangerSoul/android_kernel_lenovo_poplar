How to compile Kernel?
1. Decompress the kerenl package kerenl_5.10.tar:
 tar -zxvf kernel_5.10.tar

2. Run the script ./kernel_build.sh:
 ./kernel_build.sh

3. After the script end ,you can get the Kerenl image form:
  kernel-5.10/out/arch/arm64/boot/Image.gz

Meanwhile,you can get the complie log(kernel_build.log) in the current directory to compare with "base_kernel_build.log".


# **Description**
Rekall currently lacks the ability to generate/convert profiles for Linux compiled for ARM's Aarch64. Thus, we introduce the Rekall Profile Generator that is capable of building such Rekall profiles. The generator uses radare2 and its dwarf plugin to parse and extract DWARF information from Aarch64 ELF binaries. We support the randomized_struct_fields_(start_end) feature that was added in Linux v4.13 and higher, which define a struct region in such a way that the position of all struct elements inside this region are randomized.

# **Usage**
First, the Dwarf image of the target Linux kernel must be generated using [Rekall](https://github.com/google/rekall/tree/master/tools/linux). Second, the tool can be executed in the following way to generate the profile of the Linux kernel for Aarch64:
```
./rekall-profile-generator.py -s <path_to_linux_kernel>/System.map -c <path_to_linux_kernel>/.config -d <path_to_rekall>/tools/linux/module_dwarf.ko
```

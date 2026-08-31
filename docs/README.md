------

![](./PIC.png)

------

# UPX Killer

> 我管你三七二十一什么 UPX 魔改壳子，直接一手加载到内存 Dump 脱壳。

<p align="center">  <img src="https://img.shields.io/badge/Platform-Windows|linux-0078D4?style=for-the-badge&logo=windows" alt="Platform">  <img src="https://img.shields.io/badge/Language-C%2B%2B20-00599C?style=for-the-badge&logo=cplusplus" alt="Language">  <img src="https://img.shields.io/badge/UI-WinUI%203-5C2D91?style=for-the-badge" alt="WinUI 3">  <img src="https://img.shields.io/badge/Architecture-x86%20%7C%20x64-FF6F00?style=for-the-badge" alt="Architecture"></p>

<p align="center">  <strong> 内存 Dump · Import 重建 · Relocation 重建</strong></p>

让目标程序真正运行起来，等待壳完成解压，再从进程内存中捕获已经展开的Image，并重新构造一个可用的磁盘映像。

<br>
<br>
> [!IMPORTANT]
> 本项目部分代码由ai生成，请注意甄别
<br>
### 工作原理

UPX-Killer 会首先**加载目标程序**并运行其壳代码，在检测到壳完成解压并恢复原始程序执行环境后，**捕获**此时的进程**内存镜像**并执行 Memory Dump，将已经解压到内存中的可执行文件映像保存下来。随后程序会对 Dump 得到的文件进行**结构修复**，重新构建 Import Table，恢复程序运行所依赖的外部 API 与模块引用，并根据实际加载地址与原始映像基址之间的差异重建 Relocation Table，最终生成结构完整、可再次被操作系统正常加载执行的脱壳文件。

### ELF 脱壳环境

ELF 脱壳依赖 **WSL2** 提供真实的 Linux 加载与 `ptrace` 调试环境。使用前需要安装并启动一个 WSL2 发行版，然后在程序的“配置”页面选择对应发行版。

`wsl.exe` 只用于发现已安装的发行版；实际脱壳任务通过 Windows WSL API 启动。目标文件、相邻依赖和 Linux Host 会被暂存到独立任务目录，验证完成后再将脱壳结果复制回 Windows。

> 当前 ELF 生产能力为小端 **ELF64 x86-64 可执行文件**，支持 `ET_EXEC` 和可执行的 `ET_DYN`/PIE；ELF32 和 ELF 共享对象仍待后续扩展。
<br>
<br>

### 温馨提示


> [!NOTE]
> 当前支持 x86/x64 PE（`.exe`、`.dll`）以及 ELF64 x86-64 可执行文件的 UPX 脱壳流程。

> [!WARNING]
> 请不要对可能包含恶意代码的程序使用本项目进行逆向与脱壳！

> [!TIP]
> 对于某些无法重建的程序，可在设置里关闭自动删除临时文件，以便直接分析内存dump

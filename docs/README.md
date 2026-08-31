------

![](./PIC.png)

------

# UPX Killer

> 我管你三七二十一什么 UPX 魔改壳子，直接一手加载到内存 Dump 脱壳。

<p align="center">  <img src="https://img.shields.io/badge/Platform-Windows|linux-0078D4?style=for-the-badge&logo=windows" alt="Platform">  <img src="https://img.shields.io/badge/Language-C%2B%2B20-00599C?style=for-the-badge&logo=cplusplus" alt="Language">  <img src="https://img.shields.io/badge/UI-WinUI%203-5C2D91?style=for-the-badge" alt="WinUI 3">  <img src="https://img.shields.io/badge/Architecture-x86%20%7C%20x64-FF6F00?style=for-the-badge" alt="Architecture"></p>

<p align="center">  <strong> 内存 Dump · Import 重建 · Relocation 重建</strong></p>

让目标程序真正运行起来，等待壳完成解压，再从进程内存中捕获已经展开的Image，并重新构造一个可用的磁盘映像。

### 工作原理

UPX-Killer 会首先**加载目标程序**并运行其壳代码，在检测到壳完成解压并恢复原始程序执行环境后，**捕获**此时的进程**内存镜像**并执行 Memory Dump，将已经解压到内存中的 PE 映像保存下来。随后程序会对 Dump 得到的文件进行**结构修复**，重新构建 Import Table，恢复程序运行所依赖的外部 API 与模块引用，并根据实际加载地址与原始映像基址之间的差异重建 Relocation Table，最终生成结构完整、可再次被 Windows 正常加载执行的脱壳 PE 文件。

### 温馨提示


> [!NOTE]
> 当前主要支持 X86以及X86_64 的PE 或ELF（.exe 、.dll 、.so） 的UPX 脱壳流程。

> [!WARNING]
> 请不要对可能包含恶意代码的程序使用本项目进行逆向与脱壳！

> [!TIP]
> 对于某些无法重建的程序，可在设置里关闭自动删除临时文件，以便直接分析内存dump

# 进化内核模糊测试

标签（空格分隔）： Fuzzing

---

自从 2014 年开始的高性能 tracing 和 fuzzing

 - 2014 - High Performance Fuzzing
    - 样本选择、Engine 设计、AFL-DYNINST、Windows fork()
 - 2015 - Go Speed Tracer
    - Guided Fuzzing、二进制翻译、硬件 Tracing
 - 2016 - Harnessing Intel Processor Trace for Vulnerability Discovery
     - Intel Processor Trace
     - 使用 Intel PT 用户模式模糊测试
     - 原生 Windows 程序的持久模糊测试模式
     - 开源了 Windows 上 Intel Processor Trace 的驱动 https://github.com/intelpt
 
## 介绍

 - 内核是关键攻击面
 - 现代缓解措施利用隔离和沙盒
 - 武器化的 Exploits 也包含了内核攻击
     - Pwn2own
     - 泄露的政府 warez
 - 内核的 Vulndev 仍处于初级阶段
 
### 应用程序沙盒

IE 沙盒、IE Protected 模式、Chrome 沙盒、Adobe Reader 沙盒
### Windows 隔离/沙盒
驱动签名验证、Patchguard / Kernel Patch Protection、App Containers、ProcessMitigationPolicy
 
## Evolutionary Fuzzing

 - 2006: Sidewinder – Sparks & Cunningham 
 - 2007: Evolutionary Fuzzing System – Jared Demott 
 - 2007: Bunny the Fuzzer – Michal Zalewski 
 - 2013: American Fuzzy Lop – Michal Zalewski 
 - 2014: Nightmare/BCCF – Joxean Koret 
 - 2015: Honggfuzz – Robert Swiecki 
 - 2015: covFuzz – Atte Kettunen 
 - 2016 : Choronzon – Zisis Sialveras / Nikos Naziridis
 
在 Fuzzing 期间 trace 并提供反馈，Evolutionary 算法：

 - 评估当前输入样本的适应度
 - 管理可能的样本池
 
Evolutionary Fuzzing 的要求

 - 快速 tracing 引擎，基本块粒度的代码覆盖度
 - 快速日志，内存驻留覆盖度 map，并非每个基本块的列表
 - 快速进化算法，最小化全局 population map、最大化池多样性
 
## AFL 提供了完整的软件包

 - 传统畸变策略的多样性
 - 通过编译时插桩检测块覆盖
 - 简化的遗传算法
     - 边覆盖被编码为元组（包括覆盖度和频率），在布隆过滤器中进行跟踪
 - 使用 portable Posix API 来进行共享内存、进程创建

### 其贡献：

 - 跟踪边覆盖度、全局覆盖度map、fork server（减少目标初始化）、持久化 Fuzzing、构建可在其他工作流中重用的唯一输入样本语料库
 
### Trace Logging

 - 每个块分配一个 Unique ID
 - 每个边都是 byte map 的索引（使用 bloom filter）
 - 使用源基本块到目的基本块的ID计算哈希值
 - 每次转换的边增量 map
 - 每个 trace 很容易与整个 session 历史进行比较
 
## WinAFL

 - Ivan Fratric - 2016
 - 内存和进程的创建都使用 Windows API
 - 代码覆盖度基于 DynamoRIO
 - 基于 module 进行过滤
 - 块和边 tracing 模式
 - 持久执行模式
 
## WinAFL - IntelPT

 - Richard Johnson - 2016
 - 第一个硬件辅助的 Windows 指导型 Fuzzer
 - 第一个公开的用于 Windows 内核的指导型 Fuzzer

### 特性

 - 基于 Intel PT 的代码覆盖度引擎
 - 为解码 Intel PT trace 的在线反汇编引擎
 - 基于 module 的过滤器
 - 边跟踪模式
 - 持久执行模式
 - 内核跟踪模式
 
## 内核代码覆盖度

 - 内核代码覆盖度很难获得
 - 开源代码可以被编译器插桩
 - 二进制代码必须使用运行时插桩、静态重写或硬件引擎

### 已有工具与方法
#### 源码级

 - GCC
    - gcc --coverage
    - AFL 为 .s 中间文件添加了 hook
 - Clang
    - Clang -fprofile-instr-generate -fcoverage-mapping
    - afl-clang-fast 使用编译器 pass
#### 二进制级

 - QEMU
    - Hook Tiny Code Generator(TCG)、翻译中间语言到 Native ISA
 - BOCHS
    - Work for j00ru
 - syzygy
    - 使用 AFL 静态重写 PE32 二进制程序
    - 要求 symbols
    - 要求额外的 dev 来让 WinAFL 内核感知
 
### Intel / AMD CPUs - Branch Trace Store

 - 每个内核线程的硬件 trace
 - 和 Last Branch Record 联合起来得到边覆盖度（edge transition）
 - 某些 Hypervisor 支持直连

![image_1chpk016hjpt8265v11kceb02m.png-63.8kB][1]

最近发布用于 Windows BTS 的开源软件 https://github.com/marcusbotacin/BranchMonitoringProject
 
### Intel Processor Trace 在 Broadwell / Skylake 引入

![image_1chpk0kl71ncr1qc6vno1p9sk9413.png-53.6kB][2]

#### 优势

 - 极低的性能开销（15%的 CPU perf hit 用于记录）
 - 日志直接送至物理内存，绕过 TLB 并且 eliminate 了 cache 污染
 - 最小日志格式
    - 每个条件分支 1bit
    - 间接分支只记录目的地址
 - 解码 trace 需要额外的开销，需要定制 disassebly
 
深入了解请看 Harnessing Intel Processor Trace for Vuln Discovery
 
稀疏二进制包格式（sparse binary packet format）
![image_1chpk4cve4qa1i9mfk217pn116j1g.png-111.3kB][3]

复杂格式：使用 Intel 开源的 libipt 库解码
 
WindowsPtDriver 用于为 Windows 提供 Intel Processor Trace 的支持
PtCov Intel Processor Trace Library 为内核态驱动交互提供用户态 API，便于将任一文件 Fuzzer 转换为覆盖度驱动的 Fuzzer
 
PtCov Intel Processor Trace Library
![image_1chpk4rfs710br11qba16o1poi1t.png-65kB][4]
![image_1chpk4vli12e9bfg10o712gi1ahl2a.png-100.8kB][5]
![image_1chpk52ns11591bsu56hi0uv8c2n.png-48.6kB][6]

## 其他方法

 - Single step / branch step (BTF)
    - 每条指令到 singlestep 都启用了 int 0x1 
    - 只在分支处中断 dbgctrl msr flag
 - PMU Sampling
    - 在每个分支强制中断
    - 异步但是很慢
    - 任何架构都能运行（包括 ARM）
 - Dynamic binary translation（动态二进制翻译）
    - 尝试为驱动运行 Pin
 
## Linux Kernel Fuzzing

 - Trinity（https://github.com/kernelslacker/trinity）
    - 为 Linux 内核树构建
    - 通过 templates 实现类型感知
    - 没有覆盖度驱动
 - ”Jones has considered feedback-guided fuzzing for Trinity in the past, but found the coverage tools that were available at the time to be too slow.” 
 
### Syzkaller- 2016

 - 覆盖度驱动的系统调用 Fuzzing
    - 使用 ASAN 代码覆盖度的 GCC port 构建
    - gcc -fsanitize-coverage=trace-pc
 - 通过 /sys/kernel/debug/kcov 公开代码覆盖度
 - 模版驱动的系统调用 fuzzing
 - 严重依赖 KASAN 来捕获错误
 - ![image_1chpk95bdv131qhj1dgf1mqe1gcp34.png-40kB][7]

#### 优劣

 - 良好的工具支持
 - 监控的 WebUI
 - 良好的日志
 - Repro（重写）最小化
![image_1chpka8cn1iak1otd18161eb4srl3h.png-43.7kB][8]

缺点是工作流复杂、配置复杂，不容易重定向

### TriforceAFL - 2016

 - 基于 QEMU 做代码覆盖度跟踪的 AFL
 - 为 QEMU post-boot 添加 fork server
 - 为 API 添加序列化技术
    - 允许像 fuzzing 一个文件格式一样 fuzz API
 - 扩展了 QEMU trace 在 AFL 中的支持以用于内核
 - 为了性能考虑，在 boot 后 COW  QEMU 中的 fork()
 - 使用自定义的 hypercalls 来扩展本地 ISA（aflcall）
    - Startforkserver、getwork、startwork、endwork
 - 使用系统调用 templates / shapes
 - 序列化系统调用为文件，使用 AFL 进行 fuzzing
 - 支持系统调用序列 ![image_1chpkd9ns7epkm6to1vulsnp3u.png-27.7kB][9]

## Windows Kernel Fuzzing

内核攻击面包括任何不可信的输入

 - 用户态：系统调用、文件解析、软件中断
 - 设备：网络、USB、Firewire

两大类：结构化的输入或者 API
 
### 系统调用

 - Ntoskrnl.sys
    - Windows 系统服务
    - 约 465 系统调用
 - Win32k.sys
    - 内核态图形显示接口支持
    - 约 1216 系统调用
 - Win32k.sys 文件解析
    - 字体：TTF、OTF、FON
    - 图片：BMP、JPEG、CUR、ANI、ICO
    - 元文件：EMF、WMF
 - 其他攻击面
    - 图形驱动、音频驱动、网络驱动、打印驱动
 
### 遗产

 - Ioctlfuzzer – Dimitry Oleksander (cr4sh)
 - Misc Syscall fuzzers 
 - Misc file format fuzzers

### 技术

 - 随机系统调用参数或 ioctl 输入
 - Hook 与中断（ioctlfuzzer）
 - Dumb 或结构化文件 fuzzing

### KernelFuzzer - 2016
#### Windows 系统 API Fuzzer
 
 - API 类型感知是有效的
 - 每个类型的生成器可以手动定义，但这太繁琐
 - Pre-generated HANDLE tables
 - 输出每个测试用例的 C 代码用于在崩溃后重现
 - 可以从 TriforceAFL 风格的 API 序列生成中受益

#### Windows Graphics Driver Fuzzing
 - Windows 图形层次结构
    - Gdi32.dll -> Dxgkrnl.sys -> HW driver
 - 感兴趣的 Direct3D 函数
    - D3DKMTEscape、D3DKMTRender、D3DKMTCreateAllocation、D3DKMTCreateContext
    - ![image_1chpkkpieotkkm65ng14f616p25b.png-20.1kB][10]
 - 内部图形函数的入口点
    - 每个驱动程序实现专有格式的 *pData（几个头字段与命令数据）
    - 是进化型文件格式 fuzzing 的完美目标
 - 查找 D3DKMTEscape 的用法
    - ![image_1chpkll2n1p6bhfkj1n8qe1mna5o.png-56kB][11]
    - ![image_1chpklpdk7ir5kf1kub1jur1cmb65.png-35.4kB][12]
    - ![image_1chpklshpcrd4op6743pp9qm6i.png-86.5kB][13]
 - Intel HD Graphics Driver - igdkmd64.sys
    - 7.5MB 的图形驱动
 - NVIDIA Graphics Driver – nvlddmkm.sys
    - 800 图形处理函数

## 结论
 - 内核暴露出了大量的攻击面
 - 硬件 tracing 让代码覆盖率收集变得容易
 - 代码在 https://github.com/intelpt 处



  [1]: http://static.zybuluo.com/Titan/0k7nv56nn56b61bo9xcxhijg/image_1chpk016hjpt8265v11kceb02m.png
  [2]: http://static.zybuluo.com/Titan/jazsa4t83m5obt8vlmyglf3z/image_1chpk0kl71ncr1qc6vno1p9sk9413.png
  [3]: http://static.zybuluo.com/Titan/fd9sxk5db81un1q0ovgh7ajz/image_1chpk4cve4qa1i9mfk217pn116j1g.png
  [4]: http://static.zybuluo.com/Titan/ax5xc778nceq3cfkcagttctf/image_1chpk4rfs710br11qba16o1poi1t.png
  [5]: http://static.zybuluo.com/Titan/hij946pq14oqgmaihki99s7g/image_1chpk4vli12e9bfg10o712gi1ahl2a.png
  [6]: http://static.zybuluo.com/Titan/nd6bdradmwsp1gxse37ikh77/image_1chpk52ns11591bsu56hi0uv8c2n.png
  [7]: http://static.zybuluo.com/Titan/6vr3m9qtb5lse4byjvtajnye/image_1chpk95bdv131qhj1dgf1mqe1gcp34.png
  [8]: http://static.zybuluo.com/Titan/km3wawiio5312s5b3fpfks6n/image_1chpka8cn1iak1otd18161eb4srl3h.png
  [9]: http://static.zybuluo.com/Titan/fu15yi917wb3lnpw416fu6p2/image_1chpkd9ns7epkm6to1vulsnp3u.png
  [10]: http://static.zybuluo.com/Titan/339gzlfo25fj7n1fzdhexwxg/image_1chpkkpieotkkm65ng14f616p25b.png
  [11]: http://static.zybuluo.com/Titan/sami6pch9s5ynkuwmxbd0j0i/image_1chpkll2n1p6bhfkj1n8qe1mna5o.png
  [12]: http://static.zybuluo.com/Titan/or5zn294ja4x9lzvg3yas68k/image_1chpklpdk7ir5kf1kub1jur1cmb65.png
  [13]: http://static.zybuluo.com/Titan/8knadf268ev7npcgtfvn1f43/image_1chpklshpcrd4op6743pp9qm6i.png
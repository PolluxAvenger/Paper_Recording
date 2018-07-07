# Digtool: A Virualiztion-Based Framework for Detecting Kernel Vulnerabilities

标签（空格分隔）： Paper

---

## 论文来源
USENIX Security - 2017

## 工作介绍

Digtool 是一个二进制内核漏洞检测工具，可以截获内核执行期间的大量动态行为，例如内核对象分配，内核内存访问，线程调度，函数调用

## 工作背景

漏洞是网络攻击成功的根本原因

检测漏洞有两个方面：

 - 路径探索
 - 漏洞识别

将路径探索和漏洞识别相结合是检测漏洞的有效方法，AFLFast 和 SYMFUZZ 只采用路径探测来检测代码分支。作为路径探索的典型示例，S2E 基于虚拟化技术将虚拟机监控和符号执行结合起来以自动探索路径

漏洞识别用于在已探索的路径中记录异常（如参数滥用或非法内存访问），Digtool 关注的重点是漏洞识别

### 常见内核漏洞
UNPROBE、TOCTTOU、UAF 和 OOB 四类漏洞广泛出现在包括操作系统内核在内的各种程序中

#### UNPROBE

No checking of a user pointer to an input buffer（不检查用户指向输入缓存区的指针）会导致 UNPROBE 漏洞，许多内核模块都忽略了对用户指针的检查。根据常见漏洞和 CVE 的历史数据，Windows 内核中存在许多 UNPROBE 漏洞，UNPROBE 的漏洞可能导致无效的内存引用、任意内存读取或甚至是任意内存改写

#### TOCTTOU

TOCTTOU 漏洞的根源在于多次从用户内存中获取值，系统调用程序获取一个参数往往第一次检查，第二次使用。攻击者有机会在两个步骤间篡改参数

与上面的 UNPROBE 类似, TOCTTOU 也可能导致无效的内存引用、任意内存读取或任意内存改写。很难通过仅基于路径探索的模糊测试来检测这种类型的漏洞

#### UAF && OOB

UAF 漏洞源于重新使用已释放的内存，OOB 的漏洞是由于访问超出分配的堆或内存对象界限的内存而导致的

## 工作比较
根据检测目标的不同，漏洞识别分为两类，一类检测用户模式下的应用程序的，另一类检测内核模式

常见的大多数漏洞识别工具如 DESERVE、Boundless、LBC 等都是用户模式下的。Linux 内核的漏洞识别工具，如 Kmemcheck、Kmemleak、KEDR，但它们都依赖于操作系统的源码

而在闭源的 Windows 系统中，检查内核漏洞的有 Driver Verifier 工具，用于检测非法函数调用与参数，但并非专门检查内核漏洞的工具

目前基于虚拟化的漏洞识别工具，如 VirutualVAE、PHUKO 等，都针对单个特定类型的漏洞。基于虚拟化的工具 Xenpwn 利用 Libvmi 来发现 Xen 的准虚拟化设备漏洞

对于 Windows 这样的闭源操作系统，无法在编译时插入检测代码来检测程序错误，也无法像 Driver Verifier 那样修改系统源代码。因此我们采用虚拟化来隐藏操作系统的内部细节，并在较低级别（hypervisor）执行检测

## 工作设计
对于 Linux 系统，Google 已经发布了 AddressSanitizer 这样的工具来检测前面提到的漏洞，对于闭源的 Windows 很难构造这样的检测工具。Digtool 采用虚拟化技术在 Windows 内核和设备驱动程序中检测前述的四种类型的漏洞

Digtool 总体架构如图：
![image_1c5ba6icd1hgd1rjl1s9f11q1rq716.png-45.5kB][1]

Digtool 的子系统和逻辑模块分布在用户空间、内核空间和 hypervisor 中。图中的细箭头表示有直接调用关系或在模块之间有传递消息的直接通道，粗箭头表示两个模块通过一些事件触发机制间接地相互作用

在内核空间中, 主要工作包括设置受监视的内存区域、与管理程序通信以及拦截指定的内核函数。需要在内核空间中跟踪一些内核事件（如分配、释放内存），对于通信，由 Digtool 导出服务接口，内核代码调用这些接口从 Hypervisor 请求服务

加载程序、fuzzer 和日志分析器被放置在用户空间中, 以简化代码并使整个系统更加稳定。加载程序激活 Hypervisor 并加载用于探测程序路径的 Fuzzer。因此，日志分析器可以记录探测路径中的行为特征

### Hypervisor
Hypervisor 最重要的任务之一是监视虚拟内存访问，这是接口检测和内存检测的基础。而已有的方案都不适用：

 - 没有源码，不能通过 AddressSanitizer 之类的编译时工具来监视内存访问
 - 通过页访问权限 patch 系统异常处理程序来拦截内存引用是一种替代方法，但将在内核中引入重要的内部修改，可能会影响操作系统的稳定性
 - 二进制重写工具，如 Pin、DynamoRIO 等，在内核模式下工作很困难
 - 使用 QEMU、PEMU 可以实现对 Windows 内核的检测，但极其复杂而且即使不检测内存访问也存在性能问题

所以需要一个跟踪 Guest OS 外内存访问的机制，由于大多数程序在虚拟地址空间而非物理地址中运行。（Windows 中虚拟和物理地址之间的内存映射是非线性的）构建了一个以虚拟地址空间为核心的框架，采用与 Xenpwn 和 Bochspwn 不同的方案，基于硬件虚拟化技术的影子页面表（Shadow Page Table）来监控虚拟内存访问

#### Hypervisor 组件
Digtool 不依赖于任何当前的 Hypervisor 程序 (如 Xen 或 KVM)，其中包括三个重要的组件：VMM 基础架构、接口检测、内存检测

    VMM 即虚拟机监视器，等同于一个 Hypervisor

#### VMM 基础架构
VMM 基础架构检测硬件环境和 OS 版本以确保兼容性，然后初始化 Hypervisor 并将原始操作系统加载到 VM 中

Hypervisor 的初始化主要包括以下任务：

 - 构建 SPTs 来监视 Guest OS 中的虚拟内存访问
 - 初始化跟踪线程调度的模块
 - 建立操作系统内核与 Hypervisor 的通信，使接口检测和内存检测组件可以监视、处理某些特殊事件

#### 接口检测
接口检测在系统调用执行期间监视用户模式程序传递的参数，跟踪这些参数的使用和检查，以发现潜在的漏洞

在系统调用执行过程中，需要 SPTs 来监视用户内存空间。由于系统调用总是在内核模式下被调用，所以当处理器在用户模式下运行时，不监视用户内存。并且预留了相关的服务接口来配置系统调用的检测范围

#### 内存检测
使用 SPTs 监视在 Guest OS 中使用的内核内存来检测非法内存访问。内存检测能够设置受监视的内存区域与检测目标。当捕获到内存分配或释放事件时还可以动态校准被监视的内存区域。以此在内存访问过程中获得潜在漏洞的确切特征

### 内核空间组件
中间件（middleware）位于 Guest OS 的内核空间中，用于连接 Hypervisor 中的子系统和用户空间中的程序。例如，在加载 Fuzzer 之前可以通过配置文件设置系统调用的检测范围，然后中间件将配置信息和 Fuzzer 的进程信息从加载器传递到 Hypervisor

对于接口检测，中间件通过 work 线程记录所有行为事件到日志中。记录的数据包括系统调用号、事件类型、事件时间、指令地址和事件访问的内存。也因此，日志分析器就可以从日志文件中检测潜在的 UNPROBE 和 TOCTTOU 漏洞

对于内存检测，中间件通过 Hook 某些特定的内存函数来帮助动态校准被监视的内存。为了获得更多相关数据并降低性能消耗，还通过调用 service 接口来限制受监视内存的区域和内核代码的范围。如果发现潜在的漏洞，中间件将记录下来并通过 single-step 模式或软中断来中断 Guest OS。因此，Guest OS 可以和调试工具（如 Windbg）连接，并获取准确的上下文来分析漏洞

### 用户空间组件
用户空间有三个组件：加载器、Fuzzer 和日志分析器：

 - 加载器用于加载目标进程，此后 Digtool 为检测漏洞提供了一个处理环境。加载器还可以限制系统调用的检测范围，以及设置 ProbeAccess 事件边界的虚拟地址
 - Fuzzer 用于发现代码分支，由加载器加载。在 Digtool 中，Fuzzer 需要在检测范围内调用系统调用，并通过调整相应的参数在系统调用的代码中发现尽可能多地分支
 - 日志分析器用于发现日志文件中的潜在漏洞，根据漏洞的特点从大量记录的数据中提取有价值的信息

## 工作实现
### VMM 基础设施
VMM 基础设施的主要任务是初始化 Hypervisor 并提供一些基本的功能。初始化 Hypervisor 后，将原始 OS 加载到虚拟机中。然后，Hypervisor 可以通过设备监视操作系统

初始化流程：Digtool 作为通过 CPUID 指令检查处理器是否支持硬件虚拟化的驱动被加载到操作系统内核空间中。如果支持，VMM 基础设施将会为 Hypervisor 构建一些设备。之后，通过初始化某些数据结构（如VMCS）和寄存器（如CR4）来为每个处理器启动 Hypervisor。最后，根据原始操作系统的状态设置 Guest 操作系统 的状态。因此，原始操作系统就变成了运行在虚拟机中的 Guest 操作系统

可以参考 Intel 的开发者手册来获得更多关于硬件虚拟化的细节。本文主要研究有助于漏洞检测的模块：虚拟页监视器、线程调度监视器、CPU 仿真器、内核与 Hypervisor 间的通信、事件监视器

#### 虚拟页监视器
Digtool 使用 SPT 来监控虚拟内存访问。为降低开销，SPT 仅用于监视 fuzzer 线程，未受监视的线程使用 Guest 操作系统的原始页表

Digtool 使用稀疏的 BitMap 来跟踪进程空间中的虚拟页。BitMap 中的每一位都代表一个虚拟页。如果设置为 1，表示监视相应页面，并且 SPT 的 Page Table Entry（PTE）中的 P 标志应该被清除（注意：SPT 是根据 GPT 构建的）。访问被监控的页时会触发一个 `#PF`（Page F）异常

当 `#PF` 异常被 Hypervisor 截获，Hypervisor 中的页错误处理程序会检查 BitMap 中对应位值：

 - 为 0 表明这个页不需要监控，直接通过 GPT 更新 SPT，指令重新执行
 - 为 1 表明这个页被监控中，页错误处理程序将处理这个异常
     - 记录异常
     - 向 Guest 操作系统注入一个私有中断（0x1c），记录一些异常相关的信息（如访问的内存地址、导致异常的指令）
     - 触发另一个异常（软件中断）来连接 Guest 操作系统中的调试工具。Digtool 通过设置 Hypervisor 中的 MTF（Monitor Trap Flag，用于新版本处理器）或 TF（Trap Flag，用于旧版本处理器）来单步调试 Guest 操作系统中的指令。通过 GPT 更新 SPT，指令重新执行

![image_1c7nv570u1mor1tvtfrb1hhjsu99.png-39.3kB][2]

由于设置了 MTF 或 TF，Guest 操作系统执行一条指令后会触发 VMEXIT，Hypervisor 会重新拿到控制权。所以 MTF 或 TF 的处理程序有机会清除 P 标志，使该页再次被监控

可以禁用 MTF 或 TF 来取消单步操作

#### 线程调度监视器
Digtool 需要跟踪线程调度来确保只关注受监视的线程

在 Windows 操作系统中，`_KPRCB` 结构包含相应处理器的运行线程信息，`_KPRCB` 可在 `_KPCR` 中得到，而 `_KPCR` 的地址可以通过 FS 寄存器（x64 中是 GS 寄存器）得到。所以当前处理器运行的线程可以通过以下关系获得：

FS–>_KPCR–>_KPRCB–>CurrentThread

获得 `_KPRCB` 的方式多种多样，Digtool 采用了人工逆向和 Windows 内核的知识来分析，也可以利用 ARGOS 描述的方法来得到。当然也有其他方式来检测内核线程，如使用内核堆栈指针

在得到 `_KPRCB` 结构后，将监视 `_KPRCB` 中的 CurrentThread 成员。对 CurrentThread 的任何写操作都意味着一个新的线程处于运行态，Hypervisor 捕获后发现是受监视的线程，激活虚拟页面监视器来检测漏洞

#### 内核与 Hypervisor 通信
内核与 Hypervisor 之间的通信主要包括两个方面：

 - 内核组件向 Hypervisor 发出请求，Hypervisor 提供服务。通过服务接口实现
    - Digtool 为内核空间组件导出一些服务接口，它们可以直接由内核代码调用。服务接口通过 VMCALL 指令实现，这将触发 VMEXIT 陷入 Hpyervisor。借此，Hypervisor 的服务例程可以处理请求
 - Hypervisor 将消息发送到内核组件，内核组件处理消息。通过共享内存实现
    - Hypervisor 将捕获的行为写入共享内存并通知内核空间组件，然后内核空间组件读取并处理共享内存中的数据

![image_1c7o2gmm81ulq1tn41uav1apb1mc2m.png-34.5kB][3]

共享内存的工作流程：Hypervisor 捕获一些行为特征，将其记录到共享内存中，内核空间组件使用工作线程读取共享内存中的数据，并将特征信息记录到日志文件中

对应来说：

1. 目标模块触发一个被 Hypervisor 监视的事件时，VMEXIT 被 Hypervisor 捕获
2. Hypervisor 将事件信息记录到共享内存中。如果共享内存已满，将会在 Guest 操作系统中注入一段代码，其将通知工作线程处理共享内存中的数据（读取并写入日志文件）。如共享内存未满，将跳回目标模块
3. 通知工作线程后，注入的代码将返回到目标模块，重新执行导致 VMEXIT 的指令

### 系统调用接口检测漏洞
接口检测需要跟踪系统调用的执行过程并监视从用户模式程序传递的参数

接口检测可以监控系统调用执行从进入内核态到返回用户态的整个过程，此过程中监控内核代码对用户内存的处理过程，然后记录行为特征以分析潜在的漏洞

#### 事件监视器
在执行系统调用期间，定义和拦截不同的行为事件来实现接口检测。这些行为事件和拦截方法组成了事件监视器

事件监视器定义了十种类型的行为事件：Syscall、Trap2b、Trap2e、RetUser、MemAccess、ProbeAccess、ProbeRead、ProbeWrite、GetPebTeb、AllocVirtualMemory

多个事件的结合可以定位一个潜在的漏洞（例如两个连续的 MemAccess 事件表明存在潜在的 TOCTTOU 漏洞）

##### Syscall/Trap2b/Trap2e 事件
在 Windows 系统中，用户模式嗲用内核函数的三个入口点为：

 - 快速系统调用
 - 0x2b 中断
 - 0x2e 中断

快速系统调用使用 sysenter/syscall 指令进入内核态
0x2b 中断用于标记从用户态返回到内核态回调函数的调用方
0x2e 中断在较早的 Windows 系统中进入内核态

在 Digtool 中，通过截取中断描述符表（IDT）或 MSR 寄存器中的相应条目来跟踪三个入口点，对应三个事件

##### RetUser 事件
控制流返回到用户态时，处理器将预取用户态指令。因此，Digtool 通过监视用户态页面访问来获得返回到用户态的位置，标记为 RetUser 事件

##### MemAccess 事件
得到以上两个事件后，接口检测将记录操纵两点之间用户内存的指令。为此，通过 SPT 监视对用户内存的访问，此行为事件被标记为 MemAccess 事件
只有处理器以内核态运行时，用户态页面才被监视，这样可以显著降低开销

##### ProbeRead/ProbeWrite 事件
记录用户内存地址是否被内核代码检查过

##### ProbeAccess 事件
除了调用 ProbeForRead（即 ProbeRead 事件）或 ProbeForWrite（即 ProbeWrite 事件）函数外，内核代码还可以使用直接比较来检查用户存储器地址的合法性
如：“cmp esi，dword ptr [nt!MmUserProbeAddress(83fa271c)]”，其中 esi 寄存器存储着要检查的用户内存地址，并且导出变量 nt!MmUserProbeAddress 存储用户内存空间的边界

不能通过挂钩内核函数来拦截它，因为这个事件不是由任何内核函数处理的，也无法访问用户内存空间。我们使用了 CPU 仿真器

##### GetPebTeb/AllocVirtualMemory 事件
保证用户内存地址是合法的，Hook 相应的内核函数来拦截事件

为了减少误报，提高检测准确性，关注从用户态程序中作为参数传的用户内存。例如内核代码有时会在系统调用期间访问由 PsGetProcessPeb 函数返回的或由 NtAllocateVirtualMemory 函数分配的用户内存区域。此时，用户内存不是从用户态程序传递的参数，导致漏洞的可能性较小

#### CPU 仿真器
Hypervisor 中的 CPU 仿真器用来帮助获得常规方法难以获得的行为特征。CPU 仿真器通过解释执行 Guest 操作系统的一段代码来实现

![image_1c7og3adc1rmg1rcq1f2ce3jbd613.png-28.9kB][4]

 - DR 寄存器用于监视目的内存，对于 ProbeAccess 事件，目的内存存储用于检查用户态地址的边界。目的内存的地址可以通过加载器的配置文件来设置，然后 Hypervisor 通过中间组件获取目的内存，并通过 DR 寄存器监控内存访问
 - 当 Guest 操作系统访问目的内存时，Hypervisor 中的调试异常处理程序（DR 处理程序）将捕获它
 - 处理程序通过虚拟机（即 Guest CPU）的处理器状态更新 CPU 仿真器（即虚拟 CPU）的处理器状态
 - CPU 仿真器被激活，解释并执行引起调试异常的指令周围的 Guest 操作系统的代码
 - 由于调试异常是陷入事件，因此 CPU 仿真器的起始地址位于 Guest EIP 寄存器之前的指令处
 - 由于 ProbeAccess 关注直接比较的情况，所以 CPU 仿真器关注 cmp 指令。通过分析 cmp 指令获取从用户态程序传递的用户态虚拟地址指针，将事件通过共享内存记录在日志文件中
 - 系统调用中可能会检查多个用户态虚拟地址指针，设备驱动程序可以将目的内存中的值恢复到寄存器，然后通过将用户态虚拟地址真真分别与寄存器进行比较来检查。可以通过配置文件设置用户态虚拟地址指针的最大数量。完成最大数量的 cmp 指令或固定数量的指令后，Hypervisor 将停止解释并执行，并返回到 Guest 操作系统继续执行后续指令

#### 检测 UNPROBE 漏洞
对 于Windows内核和设备驱动程序，可以随时在结构化异常处理（SEH）的保护下访问由用户指针指向的用户内存。如果指针指向用户空间，解引用用户指针是安全的，否则会引入漏洞，本文中称之为 UNPROBE

理论上，在使用从用户态程序传递的指针之前，系统调用处理程序应检查它以确保它指向用户态空间。因此，在正常情况下，它会在 MemAccess 事件之前触发 ProbeAccess、ProbeRead 或 ProbeWrite 事件。如果在 MemAccess 事件之前没有这种类型的检查事件，则内核代码中可能存在 UNPROBE 漏洞

为了检测 UNPROBE 漏洞，我们关注 MemAccess 事件之前是否有检查事件，以及两个事件中的虚拟地址是否相同。如上所述，ProbeRead 和 ProbeWrite 事件是通过钩住内核中的检查函数直接获得的。难在于 ProbeAccess 事件。在 Windows 内核中，有很多代码通过直接比较来检查参数。只拦截 ProbeRead 和 ProbeWrite 事件会导致大量的误报

#### 检测 TOCTTOU 漏洞
TOCTTOU 漏洞有两个关键因素：

 - 从用户态程序传递的参数应该是一个指针
 - 系统调用处理程序不止一次从用户内存中获取参数

如果有两个 MemAccess 事件在相同的用户内存中获取，通过比较 Syscall/Trap2b/Trap2e 和 RetUser 事件综合判断是否在相同的系统调用中被触发，从而判断是否存在 TOCTTOU 漏洞

### 通过内存指纹检测漏洞
通过追踪内存分配，释放和访问的行为，使用基于内存占用的检测来检测内核内存的非法使用。主要是两种非法内存使用：

 - 越界堆访问，导致 OOB 漏洞
 - 释放内存的引用，导致 UAF 漏洞

为了捕获漏洞的动态特征，我们需要监视已分配，未分配和已释放的内存。访问已分配的内存是允许的，但使用未分配或释放的内存是非法的。Digtool 通过虚拟页监视器监视内核内存。非法的内存访问将被 Hypervisor 中的页面错误处理程序捕获。然后，它会记录内存访问错误或将其提交给 Windbg 等内核调试工具

中间组件有助于限制受监控页面的范围，并通过调用Digtool的导出服务接口将范围传递给内存检测。例如，当检测到UAF漏洞时，我们只关心释放的内存，所以我们需要将范围限制为释放的页面

为了跟踪分配和释放的内存，Digtool Hook 了内存操作函数，如 ExAllocatePoolWithTag 和 ExFreePoolWithTag。这些函数用于在 Guest 操作系统中分配或释放内核内存。通过内存操作函数的参数直接得到内存地址和大小

Digtool 加载前的内存分配无法检测，所以其应该尽早加载实现更精确的检测，通过设置注册表启动加载是可行的

#### 检测 UAF 漏洞
检测 UAF 在于跟踪释放的内存页，直到它们被再次分配，任何对释放内存的访问都将被标记为 UAF 漏洞

Windows 有很多内存函数，如 ExAllocatePoolWithTag、ExFreePoolWithTag、RtlAllocateHeap 和 RtlFreeHeap 以及一些包装函数（如，ExAllocatePool 和 ExAllocatePoolEx 都是 ExAllocatePoolWithTag 的包装函数）。为了避免重复记录，Digtool 只 Hook 底层内存函数

不恰当地使用 lookaside list 也会造成 UAF 漏洞，也 Hook 相应的函数，包括 InterlockedPushEntrySList 和 InterlockedPopEntrySList，以监视 lookaside list 中已释放的内存块

使用操作通过虚拟页监视器获取，释放操作通过记录对释放函数的调用来获得，并且记录调用堆栈信息便于回溯分析

Digtool 可以延迟释放那些释放的内存来延长检测时间窗口，释放的内存达到一定的大小将被释放。这样可以检测“指针p指向内存块A，在释放A后另一个程序分配了覆盖整个内存块A的内存块B，然后第一个程序的p指针试图操作内存块A”

#### 检测 OOB 漏洞
越界访问堆的内存可能导致 OOB 漏洞，监控的内存空间限制在未分配的内存区域，任何对未分配内存区的访问都会被认为是 OOB 漏洞

Digtool 使用中间组件帮助校准未分配的内存区域。通常来说，除内核模块和堆栈占用的内存外，都被定义为初始未分配额诶内存区。随着内核内存状态不断变化，需要 Hook 分配/释放内存的函数

Digtool 搜索已分配和未分配内存区的记录，建立一个 AVL 树（自平衡二叉搜索树）来提高内存搜索的性能。该树在分配内存时添加节点，释放内存时删除节点。当监控到访问页时，Digtool 会在 AVL 树中搜索所访问的内存区域，如果找不到相关节点，则可能存在 OOB 漏洞（值得注意的是，内存虚拟化的监控粒度是页，而内存区域的大小可以小于一页，监控页通过 BitMap 记录，而监控内存区域存储在 AVL 树中）

由于对未分配内存的检测中包含已释放的内存，因此访问释放的内存可能会导致 OOB，这需要一些逆向工程的能力还进一步区分 OOB 和 UAF 漏洞

对于两个内存块相邻，对内存块 A 的操作越界到内存块 B 中的问题，Digtool 在 Hook 内存分配函数时为其多分配 M 字节的额外内存区。但 AVL 树的节点中内存块的大小不增加，这样越界操作会访问额外分配的内存区，从而触发 OOB 漏洞

## 工作评估
Digtool 支持 Windows XP/Vista/7/8/10，但实验使用 Windows 7 和 Windows 10

### 检测潜在的 UNPROBE 漏洞
被测驱动程序仅使用 ProbeForRead 和 ProbeForWrite 函数来检查用户指针（这是第三方驱动程序中的常见情况），因此无需人工进一步确认，由于输入缓冲区的起始地址和长度信息可以通过相应的内核函数获得，检测是精确的

如果驱动程序使用直接比较来检查用户指针，则 Digtool 可能会产生误报。这是由于 ProbeAccess 事件中缺少准确的地址范围，我们无法获得输入缓冲区的大小。我们必须假设输入缓冲区的长度

### 内存指纹检测漏洞
发现程序错误时，中间组件被设置为中断 Guest 操作系统并连接到 Windbg，而不是仅记录，从而提供确切的上下文

#### 检测潜在的 UAF 漏洞
Digtool 触发了“单步异常”。由于这是一个陷入事件，触发异常的指令已经完成，Guest 操作系统在下一条要执行指令的地址处被中断

0x96b50f3e之前的指令是尝试访问释放的内存区域并导致 UAF 漏洞的指令。我们可以通过 Windbg 到达环境现场，地址为 0x96b50f3b，此时 esi 寄存器就存储着释放的堆地址

![image_1c7pu7endj9j92o1gocpsltdf1g.png-6.4kB][5]

### 性能损失
不论记录与否，大多数被监控的系统调用比 Windows 原生慢几十倍（这取决于参数和系统调用），但是仍然比 bochs 快得多

### 优势
#### Crash Resilient
Digtool 能够捕捉潜在漏洞的动态特征，而不需要“蓝屏死机”（BSOD）。由于分析过程只需要包含访问的内存地址、事件类型和事件时间的记录数据，因此不需要触发 BSOD 来定位程序错误

Fuzzer 只需要发现尽可能多的代码分支，并且不必崩溃操作系统。在此过程中，Digtool 将记录所有动态特性。如果没有 BSOD，也会继续录制，这有助于发现更多漏洞

但是，Driver Verifier 不可避免地会导致 BSOD 找到并分析漏洞。它不会停止在相同程序错误的地址处崩溃操作系统，直到错误得到解决。这将使其难以测试其他漏洞

#### 在确定的上下文中断操作系统
通过中间组件，Digtool 可以设置为在发生程序错误时中断 Guest 操作系统，同时连接到调试工具为漏洞分析提供确切的上下文

Driver Verifier 必须使操作系统崩溃才能找到并分析程序错误，但是 由于操作系统往往才程序发生错误时不停止，而是运行一段时间，此时上下文已经更改，定位问题所在需要更多的精力

#### 捕获更多漏洞
Digtool 可以有效检测 UNPROBE 和 TOCTTOU 漏洞。但是，由于没有设计类似的检测规则，Driver Verifier 不能检测它们。此外，Driver Verifier 有时可能会错过 UAF 或 OOB 漏洞，因为该漏洞可能发生在访问有效的内存页面，并且不会导致 BSOD。因此，Driver Verifier 找不到它们

## 问题与思考

Digtool 的局限：

 - 尽管其比仿真器快，但监视线程的性能开销仍然很高，性能开销主要来自 Hypervisor 和 Guest 操作系统之间的频繁切换
 - 目前仅支持 Windows 系统，Hypervisor 在 Guest 操作系统外运行，所以修改中间组件即可支持各种平台
 - 可以扩展检测算法来检测其他类型的漏洞，如竞态条件 

[论文地址][6]


  [1]: http://static.zybuluo.com/Titan/ie9l50qyol617usi1rw8sskb/image_1c5ba6icd1hgd1rjl1s9f11q1rq716.png
  [2]: http://static.zybuluo.com/Titan/cmhk5igq0y3kdh5bcjnpf0f6/image_1c7nv570u1mor1tvtfrb1hhjsu99.png
  [3]: http://static.zybuluo.com/Titan/liug3144n9flqxfvv9l51dd4/image_1c7o2gmm81ulq1tn41uav1apb1mc2m.png
  [4]: http://static.zybuluo.com/Titan/ganjq8zwvastxju3gmlspuli/image_1c7og3adc1rmg1rcq1f2ce3jbd613.png
  [5]: http://static.zybuluo.com/Titan/g2g9civyokpx35r5ttesqun5/image_1c7pu7endj9j92o1gocpsltdf1g.png
  [6]: https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-pan.pdf
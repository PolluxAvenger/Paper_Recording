# Bochspwn 介绍

标签（空格分隔）： Fuzzing

---


理想情况下，单个系统调用内，在 ring3 的每个字节：

 - 安全地只读一次
 - 安全地只写一次，仅限那些送给用户态的数据

事实上

 - 不一定安全地读只读一次
 - 不一定安全地写只写一次

## 用户与内核间的 API
有显著差异的高级接口
 
 - 内核在本地使用 C、C++、汇编实现
 - 语言中数组、struct 等典型对象提供的信息
 - 堆和栈中分配的内存通常不为零
 - 假设在目标系统中执行代码的可行性，所以要由内核返回的所有字节的直接访问

## 各种问题
![image_1ciecblvb18bb9sbb1214va1n8t9.png-119.1kB][1]
如果 InputValue == 0，OutputValue 就未被初始化

![image_1ciecij88186j1q01idu1r0f1j0m.png-161.5kB][2]
因为是“保留”，初始化的时候就没有被赋值

![image_1cieoeqf9qrrmvvnp31km65de13.png-168.4kB][3]
高 32 位因为未被使用，所以未初始化

![image_1cieoj3al1hpejp71osd1c6asb61g.png-196.2kB][4]
未初始化的填充区域

![image_1cieomle64sip1p1auvdei1es52d.png-270.7kB][5]
固定大小数组中未被使用的区域

![image_1cieovn4fe8984t97cdr105b3a.png-246.8kB][6]
未使用也未初始化的数据部分

### 不自动初始化
一般情况下，Windows 与 Linux 都没有对堆栈中的新对象进行初始化

 - 也有一些例外，主要是在 Linux 上，kazlloc()、__GFP_ZERO、PAX_MEMORY_STACKLEAK 等
 - 所谓缓冲区，缓冲的 ioctl 在 Windows 2017 年 6 月新加入

![image_1ciep8vfitk0mv9l5n1k2o1ssb47.png-37.1kB][7]

### 缺乏一致性
C/C++ 没有为在域之间安全地数据传输进行设计

## 数据泄露
![image_1ciepfs23ere1ggp14s41tkbo5s4k.png-45.5kB][8]

只有本地数据被泄露，无法启动或利用远程代码。其危险程度取决于究竟可以从内核泄露什么。而且多数的泄露不会留下痕迹，不用担心系统的稳定性会受到影响

### 使用数据泄露
常用于权限提升中的 KASLR 和内核模式地址空间保护

CVE-2015-2433，MS15-080 实例

 - 堆内存泄露系统驱动 Win32k.sys 中的地址
 - Matta Taita 独立发现

![image_1cieptnl6hade21o3cfah1f4c51.png-154.9kB][9]

蓝色为内核代码地址（ntoskrnl.exe）、紫色为内核堆栈地址、绿色为内核堆地址（非分页池）

 - 堆和可执行模块分配的内存地址
 - 任何数据控制器：磁盘、网络、外设等

![image_1cieq4l653upa8ddfipa61vao5u.png-103.8kB][10]

![image_1cieq6pb115mb1io2dm51p7d10ak6b.png-130.4kB][11]
蓝色为大分配（非分页），紫色为小分配（非分页），绿色为小分配（分页）

## 从前的研究（Windows）

 - NtGdiGetTextMetrics(CVE-2015-2433)
 - 奇虎 360 的自动发现 Windows 内核中的信息泄露

## 从前的研究（Linux）

 - 2010 年 Dan Rosenberg 报告内核中发现的二十多个不同的内存泄露
    - 讲座 Stackjacking and Other Kernel Nonsense 中提出的一些研究是他和 Jon Oberheide 在 2011 年提出的
 - 多年来通过研究大量的补丁提交

## Bochspwn Reloaded

 - IA-32 与 AMD64 的全仿真工具，CPU 与所有的基本设备
 - 使用 C++ 编写
 - 支持最新的处理器及其扩展（SSE、SSE2、SSE3、SSSE3、SSE4、AVX、AVX2、AVX512、SVM/VT-x 等）
 - 基本支持流行的操作系统
 - 提供 API 支持对仿真代码的插桩

### 性能
IPS 80-100M，足以在合理的时间（5-10分钟）运行系统，GUI 显示大约每秒 1-5 帧。插桩会增加开销，Bochspwn Reloaded 的性能会下降到 IPS 30-40M

## 基本思路
污点跟踪整个内核地址空间，基本功能：

 - 堆和栈的新分配内存时增加污点
 - 堆释放内存时删除污点
 - 复制数据时指定内存
 - 检测标记的内存
 - 当前加载的内核模块
 - 检测到错误时，读出调用堆栈
 - 地址符号存储在报告中
 - 检测内核调试工具控制转移的错误

### 影子内存
![image_1cier382f13en1t9empmvol1e4b6o.png-56.6kB][12]

 - 相对于客户机操作系统的内核地址空间的大小呈线性关系，所以只支持 32 位系统
 - 最大内存使用
     - Windows（2GB 内核空间）- 6GB
     - Linux（1GB 内核空间）- 3GB
 - 主要的开销就是主机必须有足够多的内存

### 堆栈分配的检测
栈分配的检测简单、用途广泛、系统无关，主要针对 ESP 寄存器修改的指令检测：

 - ADD ESP
 - SUB ESP
 - AND ESP

完成后，如果 ESP 减少则称为：set_taint(ESP<sub>old</sub>, ESP<sub>new</sub>)

堆的分配就需要专用于特定的系统，需要跟踪地址与分配的大小两者，即：set_taint(address, address+size)

### 污点传播
检测数据复制是最难的部分，Bochspwn 传播的表示为 `<REP> MOVS{B,D}`

 - 通过各种形式使用的 memcpy()
 - 源地址（ESI）与目的地址（EDI）需要同时知道
 - 对整个存储区域的完整副本感兴趣
 - `<REP> MOVS{B,D}` 向内存写入即为初始化

### 错误检测
指令 `<REP> MOVS{B,D}` 有没有源地址为内核空间，目的地址为用户空间的污染传播

 - 检查污染的整个复制区域
 - 如果至少有一个字节未被初始化，就报告错误

## Bochspwn VS. Windows
### 实施细则

 - 堆分配归结为两个函数 ExAllocatePoolWithTag 和 ExfreePoolWithTag
 - 拷贝内存接管 rep movs
 - 优化分配器，如 win32kAllocFreeTmpBuffer
 - 优化的 memcpy 长度小于 32

![image_1cilq0egq1evc1a21hd07roq5oc3.png-82.8kB][13]

![image_1cilq1nb6t19ub6t1n6o81rb9cg.png-129.6kB][14]

Windows 7 的内核内存
![image_1cilq3a3sfhc2vr1m7lekh2vuct.png-40.8kB][15]

Windows 10 的内核内存
![image_1cilq4agi1vha2bd863q311bovda.png-62.3kB][16]

### 示例错误报告
![image_1cilq5ruk1c0qjo7lf33q8m4hdn.png-65.4kB][17]

### 内核调试器支持
Bochspwan 的文字报告很详细，但并不足够重现错误。特别是对于 IOCTL 和其他复杂情况下，必须钻研系统状态和环境

解决方案：windbg 挂钩仿真系统内核

 - 易于配置，Bochs 可以配置 Windows 的 COM 端口的 pipe
 - 免费

### 泄漏点分析

如果不能恰好在泄露内存时调试系统，需要将报告保存成文件，产生 Bochspwn INT3 异常

rep movs 指令后立刻停止 windbg
对 x86 模拟器通过额外的插桩产生异常，该异常需要挂在仿真内核调试器

![image_1cilqgh6sqrq1udphrtajai9ne4.png-187.2kB][18]

### 结果

 - 调试系统
 - 使用若干默认应用程序，IE、写字板、注册表编辑器、控制面板、游戏等
 - 产生网络流量
 - 启动 ReactOS 的 ~800 单元测试项目

六个月四十个漏洞
![image_1cilqkhd73ftr691vl419mj19lneh.png-60.3kB][19]
![image_1cilqlea14jaakv1jr2ei314uneu.png-79.3kB][20]

### 泄漏的复现

 - 使用了常用的 Windows 虚拟机的版本
 - 检查公开的（如 win32k.sys）驱动程序分配内存
 - 打开 Special Pools 机制并重启系统
 - 双击运行，看到 PoC 重复字节标记在数据泄露中

![image_1cilqppim42euena6tp797asfb.png-31.5kB][21]

难以确定系统调用输出的哪些字节是它们初始化的

### 来自 Stack Spraying 的帮助

 - Windows 内核提供了几个函数来帮助大区域堆复制
 - 很容易找到，一个名为 Nt* 的函数与 IDA Pro 名单中的最大堆栈帧函数
 - 我最喜欢 nt!NtMapUserPhysicalPages
     - 填补了堆栈上 4096/8192 字节用于 x86 和 x86-64
     - 记录在 2011 年 nt!NtMapUserPhysicalPages and Kernel Stack-Sparying Techniques

内核堆栈
![image_1cilrl8ti18jqctr128cvuhds1fo.png-22.3kB][22]
使用容易识别的字符填充内核栈

![image_1cilrop2nqmak8ce491lp91vsog5.png-52kB][23]
泄露后，可以看到有未初始化的数据

![image_1cilsmqvo1u09valn63k25t9agi.png-20.4kB][24]

CVE-2017-8470（win32k!NtGdiExtGetObjectW）
![image_1cilspelk7uk1d1u1dei12011c5gv.png-73kB][25]
CVE-2017-8479（nt!NtQueryInformationJobObject）
![image_1cilsruq01rr51iql96g1qags7ehs.png-46kB][26]
CVE-2017-8490（win32k!NtGdiEnumFonts）
![image_1cilsv4ga106jqkb1r9a1hu83sti9.png-98.6kB][27]
CVE-2017-8489（WmiQueryAllData IOCTL）
![image_1cilt0it41p0s2tcil915211l75im.png-65.2kB][28]

### Windows 总结

 - Windows 采取一种非常宽松的方式来复制内核和应用程序之间的数据
 - 上百个调用 memcpy 将数据复制到内核空间潜在地导致泄露

### 改进

Bochspwn 还有改进的空间：

 - 支持 x86-64
 - 内核代码的覆盖度
 - 针对微软优化更好的污点传播
     - 编译时插桩比运行时插桩更好

## Bochspwn VS. Linux

### 测定堆分配

 - 许多不同的分配器，公开的非公开的，还有不同的变体：kmalloc、vmalloc、kmem_cache_alloc
 - 不同的函数与不同的分配语句
 - 通过寄存器传递（regparm=3），这意味着分配信息在执行 RET 指令时不可用
 - 对象 kmem_cache 定义了创建分配的大小
 - 对象 kmem_cache 可能有“构造”
 - 分配器可以以 ≤ 0x10 为返回值（不止 NULL）

### 污点传播
CONFIG_X86_GENERIC=y 和 CONFIG_X86_USE_3DNOW=n 
memcpy() 要翻译成 rep movs{d,b}

Ubuntu 16.04
![image_1cilk1mt3vntedc1smnu5cqp5c.png-37.1kB][29]

### 错误检测：copy_to_user
配置 CONFIG_X86_INTEL_USERCOPY=n 意味着 copy_to_user() 被编译为 rep movs{d,b}

![image_1cill2dsv1g8tfm52u712m73lv2p.png-74kB][30]

### 错误检测：put_user

 - 不基于 memecpy() 所以不是正常的检测
 - 每个架构，包括 x86 都有自己的实现
 - 很难通过宏转换为 memecpy
     - 参数传递不同的结构，固定的、可变的等等

临时解决方案：严格模式
![image_1cille89rsjoefp7js49q14ds4i.png-75.4kB][31]

 1. 打开严格模式（对于当前的 ESP）
 2. 解决传递
 3. 关闭严格模式

### 严格模式

 - 说明 PREFETCH{1,2} 操作 Bochs 中的 NOP
 - PREFETCH1 和 PREFETCH2 之间未初始化的内存泄漏被报告为内核→用户
 - 365 块添加到 Bochspwn 所使用的镜像 vmlinux 中

### put_user 在 IDA Pro 中看到
![image_1cilltu9fgp9kn1d981nfs17qk6o.png-113.7kB][32]

### 示例错误报告
![image_1cilluncubbnlajq1c1oj11q2l78.png-70.8kB][33]

### 内核调试
![image_1cillvnv112aakbtlrqjq51dn85.png-194.9kB][34]

### 测试
插桩 Ubuntu 16.10 32位（4.8内核）

操作：

 - 调试系统
 - SSH 登录
 - 从 /dev 和 /proc 开始执行一些基本的命令
 - 列入首发单元测试 Linux Test Project(LTP)
 - 启动系统调用 Fuzzer，Trinity 和 ikonwthis

最好使用 syzkaller，但它缺乏对 x86 的支持（仅支持 x86-64 和 arm64）

## 结果
Bochspwn 可以检测到所有对未初始化内存的引用
![image_1ciln96tk191j18dv1pptv9215l79i.png-76kB][35]

### KernelMemorySanitizer

大多数与 KMSAN 重复

 - 编译时插桩，检测用户对未初始化内存的使用
 - 和 KernelAddressSanitizer 与 MemorySanitizer 是结对项目

## 其他方法
### 替代方法

 - 手动审计 memcpy 配套的系统调用（CVE-2017-8680、CVE-2017-8681）
 - 比较两次系统调用输出的不同之处（CVE-2017-8478、CVE-2017-8479、CVE-2017-8480、CVE-2017-8481、CVE-2017-0300）
 - bindiff 内核与 Windows 不同版本的驱动程序（CVE-2017-8684、CVE-2017-8685）

### 没有污点跟踪的 Bochspwn

 - 堆栈中的所有分配都设计一个通用的模式
 - 对每个内核到用户的记录，都要查看其保存的数据是否是模式的一部分
 - 研究中使用的想法：Automatically Discovering Windows Kernel Information Leak Vulnerabilities

优点：高效、节省资源、不需要使用完整的 x86 模拟器、可检测其他地方的泄露（比如网络流量、文件系统）
缺点：误报

## 其他位置的泄露
![image_1cilo7vj91337vsmgs11c7lo259v.png-66.3kB][36]

文件系统的数据结构表示相当复杂，物理攻击场景：

 - 攻击者要求受害者访问 USB 驱动器或者记忆卡中的文件
 - 受害者将文件复制并发送给攻击者
 - 攻击者得到镜像内存，获得受害未初始化内核内存部分

结果是 FAT\FAT32\exFAT 都缺乏，而 Windows

CVE-2017-11817: $LogFile 文件泄露
![image_1cilofqj61egjvoq1r2s87dd6tas.png-252.1kB][37]

 - 每个 NTFS 分区包含一个内部文件 $LogFile
 - 读取原始设备
 - 安装文件系统时直接初始化

![image_1cilohmde11cdd661teh6m0gh0b9.png-21kB][38]

### restart 区域
$LogFile 文件的头部有 4096 字节的 restart 区域

从堆中分配 Ntfs!LfsRestartLogFile

 - Windows7 以上的系统不重置区域
 - 大多数不保存之前的任何数据初始化

超过 700KB 的“垃圾”在内核内存连接外部驱动器的自动存储

![image_1cilotndk69ajeglic1sgfuktbm.png-68.1kB][39]

### 没有受害者参与的方案

 - Windows 会自动安装物理连接设备的文件系统，即使在计算机被锁定时
 - 通过 USB 从内核吸取敏感数据


  [1]: http://static.zybuluo.com/Titan/u1rewj55v69j7qy3fzybtb4l/image_1ciecblvb18bb9sbb1214va1n8t9.png
  [2]: http://static.zybuluo.com/Titan/a1hqytfa4avppbpqq4iggh4q/image_1ciecij88186j1q01idu1r0f1j0m.png
  [3]: http://static.zybuluo.com/Titan/hs4lqj7pre2ou84a55otk4jw/image_1cieoeqf9qrrmvvnp31km65de13.png
  [4]: http://static.zybuluo.com/Titan/qp9bvz9etqxknwqy66ozrkw2/image_1cieoj3al1hpejp71osd1c6asb61g.png
  [5]: http://static.zybuluo.com/Titan/ivjuy4b7e699iz37kzs3mywr/image_1cieomle64sip1p1auvdei1es52d.png
  [6]: http://static.zybuluo.com/Titan/yaysefjvf6f9sxk7l1nzbsli/image_1cieovn4fe8984t97cdr105b3a.png
  [7]: http://static.zybuluo.com/Titan/yf1j6qpacmi60446swavedwv/image_1ciep8vfitk0mv9l5n1k2o1ssb47.png
  [8]: http://static.zybuluo.com/Titan/f2tfdexmrs7pefinqiuej8fy/image_1ciepfs23ere1ggp14s41tkbo5s4k.png
  [9]: http://static.zybuluo.com/Titan/yz359y3jpvhxa9t0kxcla3rj/image_1cieptnl6hade21o3cfah1f4c51.png
  [10]: http://static.zybuluo.com/Titan/u85sg6z2kueqpw968prj41fv/image_1cieq4l653upa8ddfipa61vao5u.png
  [11]: http://static.zybuluo.com/Titan/o6vlgs9dnwcbap1dsctvv5lp/image_1cieq6pb115mb1io2dm51p7d10ak6b.png
  [12]: http://static.zybuluo.com/Titan/liwfck6b89zng1l4rdvr24x7/image_1cier382f13en1t9empmvol1e4b6o.png
  [13]: http://static.zybuluo.com/Titan/yvto8armvxbxuu109pcohksh/image_1cilq0egq1evc1a21hd07roq5oc3.png
  [14]: http://static.zybuluo.com/Titan/evm9orp9nbm73h8452l81bkh/image_1cilq1nb6t19ub6t1n6o81rb9cg.png
  [15]: http://static.zybuluo.com/Titan/vdlultq54d9bfvywavjsgsff/image_1cilq3a3sfhc2vr1m7lekh2vuct.png
  [16]: http://static.zybuluo.com/Titan/df0s5y632dutyagwle1rqi4c/image_1cilq4agi1vha2bd863q311bovda.png
  [17]: http://static.zybuluo.com/Titan/exswp74oi4i06q4w834trn58/image_1cilq5ruk1c0qjo7lf33q8m4hdn.png
  [18]: http://static.zybuluo.com/Titan/1up65m08raz055gxiir74azv/image_1cilqgh6sqrq1udphrtajai9ne4.png
  [19]: http://static.zybuluo.com/Titan/ytpy15uikt1jal838k7bu3ce/image_1cilqkhd73ftr691vl419mj19lneh.png
  [20]: http://static.zybuluo.com/Titan/shrhkzu9xiu3pz5yipf9whzb/image_1cilqlea14jaakv1jr2ei314uneu.png
  [21]: http://static.zybuluo.com/Titan/3mn9zegrcrs03q51xr5brjf3/image_1cilqppim42euena6tp797asfb.png
  [22]: http://static.zybuluo.com/Titan/r7fz279i02kuku1mj947rqfk/image_1cilrl8ti18jqctr128cvuhds1fo.png
  [23]: http://static.zybuluo.com/Titan/d2pp25gvnztj5an6ghlektut/image_1cilrop2nqmak8ce491lp91vsog5.png
  [24]: http://static.zybuluo.com/Titan/65w5picr89x6eemlg5qd45f4/image_1cilsmqvo1u09valn63k25t9agi.png
  [25]: http://static.zybuluo.com/Titan/c694i2j6q8f8yxyorzlpt5fz/image_1cilspelk7uk1d1u1dei12011c5gv.png
  [26]: http://static.zybuluo.com/Titan/xhnljxwqaskyh3jxpxpc1310/image_1cilsruq01rr51iql96g1qags7ehs.png
  [27]: http://static.zybuluo.com/Titan/o56xxkyd3iekh8ce56fnb25k/image_1cilsv4ga106jqkb1r9a1hu83sti9.png
  [28]: http://static.zybuluo.com/Titan/4f8lcxhbtf0bszc9ksrxznhh/image_1cilt0it41p0s2tcil915211l75im.png
  [29]: http://static.zybuluo.com/Titan/r4j29h1ay3niv4f9yfwwm13b/image_1cilk1mt3vntedc1smnu5cqp5c.png
  [30]: http://static.zybuluo.com/Titan/dfl29yu9g3979nj24sib6el0/image_1cill2dsv1g8tfm52u712m73lv2p.png
  [31]: http://static.zybuluo.com/Titan/kp7cxnqgvhrb7sz6el38r37l/image_1cille89rsjoefp7js49q14ds4i.png
  [32]: http://static.zybuluo.com/Titan/56xm46ag4wabexbo490nfz3s/image_1cilltu9fgp9kn1d981nfs17qk6o.png
  [33]: http://static.zybuluo.com/Titan/5ytmmlt8392w2v3gvfppn5yx/image_1cilluncubbnlajq1c1oj11q2l78.png
  [34]: http://static.zybuluo.com/Titan/krbk302nx2bzmmtsfrwgka26/image_1cillvnv112aakbtlrqjq51dn85.png
  [35]: http://static.zybuluo.com/Titan/ofh1w0ov8ajhxozst6v0vjtp/image_1ciln96tk191j18dv1pptv9215l79i.png
  [36]: http://static.zybuluo.com/Titan/5h5tkv3d3jttynib7nvfo37e/image_1cilo7vj91337vsmgs11c7lo259v.png
  [37]: http://static.zybuluo.com/Titan/xz5p2fybw08w4zmp1s37q9el/image_1cilofqj61egjvoq1r2s87dd6tas.png
  [38]: http://static.zybuluo.com/Titan/emrupldczwj2j7fhntzx4ody/image_1cilohmde11cdd661teh6m0gh0b9.png
  [39]: http://static.zybuluo.com/Titan/ksq4zp7jtsip84l105ew0nd6/image_1cilotndk69ajeglic1sgfuktbm.png
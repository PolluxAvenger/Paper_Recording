# Bochspwn 进化

标签（空格分隔）： Fuzzing

---

## Reloaded

![image_1cio36kmj1oqm11eq1954dp10699.png-38.9kB][1]

实际遇到的问题：

 - Double Fetches
 - Double Writes
 - Read-after-write conditions
 - Unprotected accesses to user-mode pointers

### 内核内存泄露的原因

 - 基本类型的未初始化变量
 - 未初始化结构体变量（如，reserved）
 - 结构体尾部和中间的填充字节
 - 使用不同大小的字段的联合体中的未使用字节
 - 固定大小数组的部分填充
 - 任意系统调用输出缓冲区的大小

### 内核内存泄露的影响因素

- 动态对象与自动对象没有默认的初始化
    - 也有一些例外，主要在 Linux 上
- 对开发者或者终端用户的后果不可见
- 泄露隐藏在系统 API 后
    - 被系统 DLL 丢弃，对合法应用程序不可见

### 内核内存泄露的严重性

 - 只是本地信息泄露，没有内存破坏或者天然的远程利用
 - 实际地严重程度取决于内核泄露出来什么
 - 在 LPE 利用链中最有用的一环
    - 内核态地址和 Stack Cookie 是最容易泄露的
    - 从 heap/pool 潜在地也许可以泄露其他敏感信息

![image_1cio5ed1c15p01okkgsp80kkph16.png-105.7kB][2]
蓝色为内核代码地址（ntoskrnl.exe），紫色为内核栈地址，绿色为非分页池地址

### 相关工作-Windows

 - P0 Issue #480 (win32k!NtGdiGetTextMetrics, CVE-2015-2433), Matt Tait
 - Leaking Windows Kernel Pointers, Wandering Glitch, RuxCon, October 2016
 - Automatically Discovering Windows Kernel Information Leak Vulnerabilities
 - Zeroing buffered I/O output buffer in Windows

### 相关工作-Linux

 - 检测
    - 个别研究， Rosenberg 和 Oberheide 发现 25 个 bug(2009-2010)、Krause(2013) 发现 20 个 bug
    - -Wuninitialized
    - kmemcheck
    - 使用 Coccinelle 进行静态分析（2014-2016）
    - UniSan（2016）
    - KernelMemorySanitizer（2017）
 - 缓解
    - 主线：CONFIG_PAGE_POISONING、CONFIG_DEBUG_SLAB
    - grsecurity/PaX：PAX_MEMORY_SANITIZE、PAX_MEMORY_STRUCTLEAK、PAX_MEMORY_STACKLEAK
    - Secure deallocation (Chow et al., 2005)
    - Split Kernel (Kurmus and Zippel, 2014)
    - UniSan (Lu et al., 2016)
    - SafeInit (Milburn et al., 2017)

### Bochs 插桩回调
![image_1cio7r26jvsgtlba7v1fl6mkq1j.png-83.4kB][3]

### 核心逻辑
污点跟踪整个内核地址空间，主要功能：

 - 在新分配处设置污点
 - 在所有内存写入处移除污点
 - 在 memcpy() 处传播污点
 - 检测被污染的内存传播到用户态

影子内存（32-bit）
![image_1cio8amkr1km7pnkbmkuep1fh053.png-64.1kB][4]

### 污点跟踪行为
![image_1cio8d609e3omd1165n1ga9suf5g.png-92kB][5]
![image_1cio8em0q157mrmv39r1ruq1tdt6d.png-90.4kB][6]
![image_1cio8jqb3tn11v2fqoj1g01aih9d.png-91.7kB][7]
![image_1cio8l6ipo63khv1sgu16fh154o9q.png-97.6kB][8]
![image_1cio8mhf313ks8hn1p6t56df8da7.png-105.9kB][9]

### 辅助功能

 - 跟踪加载用户内核模块
 - 读取错误堆栈跟踪，删除重复 bug
 - 符号化调用堆栈来整理报告
 - 错误处挂起内核调试器

### Windows Bug Report
![image_1cio994vr19otom11beqgt1apbak.png-97.2kB][10]

系统启动，使用默认应用，生成一些网络流量，运行 800 ReactOS 单元测试，运行 30 NtQuery 自定制的测试套件

![image_1cio9e06lb4a5vllc61c4o1jq4ch.png-72.9kB][11]
![image_1cio9eu8fd9t15uc42de6p1htpcu.png-149.4kB][12]
![image_1cio9g6oo1i86148u350l5d1cufeb.png-144kB][13]
![image_1cio9gg8c9lad5v1rlk7i81t4reo.png-104.9kB][14]

### Linux Bug Report
![image_1cio9mgrl2mihs9deohju1j7jhl.png-103.8kB][15]

系统启动，SSH 登录，执行几个程序，在 /dev 和 /proc 下读取文件，运行 LTP 单元测试，运行 Trinity 和 iknowthis
![image_1cio9p6o51d9cgsr183hbsln1ai2.png-105.9kB][16]

## 支持 x64 的挑战与结果
![image_1cio9rt441cu8bbtccqu5g2a5is.png-42.6kB][17]

### 增加对齐 increased alignment
![image_1cioa73if7ug1fe3annum51ajnj9.png-62.2kB][18]

### 增加字段大小
![image_1cioa7g5qeph1q741g5e17ml1u7ljm.png-65.8kB][19]

### 问题1：影子内存表示

对于 x86 系统，影子内存静态分配三倍的内存开销
对于 x64 系统，内核地址空间从 0xffff800000000000 到 0xffffffffffffffff，总计 128T，不可能分配等量的用户态内存空间

 - 消除一些不太重要的元数据类
 - 存储分配的原始容器从静态数组变为 hash map
 - 使用 bitmask 优化污点表示
    - 保留了 18T 的区域，用户地址空间的 1/8。back only the required pages with pyhsical memory
    - Windows 不支持 overcommit
    - 使用向量化的异常处理实现自定义的 overcommit

定制的 overcommit
![image_1ciof688a9sunfn1t8714q910m6k3.png-302.9kB][20]
影子内存表示
![image_1ciof6pknrcg1cc81n811ctjpdnkg.png-67.5kB][21]

### 问题2：检测数据传输

 - x86 - 标准库的 memcpy 大多使用 rep movs
    - 容易在 Bochs 插桩
    - 源地址、目的地址与拷贝尺寸同一时间都能知道
 - x64 - 更困难，memcpy 优化使用 mov 和 SSE 指令
    - 寄存器未被污染，以前的逻辑行不通
    - Patching 不是个好选择，每个驱动都有自己的函数副本

实现上的差异
![image_1ciog1dr31vt9136n1mp61d8jf3kkt.png-168.9kB][22]

使用二进制签名识别 memcpy 函数序言
![image_1ciog325s19l51t29od43td99jla.png-61.7kB][23]

未解决的是 aggressive inlining，随着 Windows 的更新，越来越多带有常量大小的 memcpy 系统调用 unrolled

![image_1ciog70dpnqks9pllo1chlroeln.png-20kB][24]
图为内核中显式调用 memcpy 的数量

win32k!NtGdiCreateColorSpace
![image_1ciog9bhp5f611ic1i8rdnqcm0m4.png-148.9kB][25]

### 问题3：展开调用栈
#### x86
栈帧被保存的 EBP 则值链在一起，调用栈可以通过插桩进行遍历，没有进一步的要求
![image_1cioh2rdemvl12oj3bmcnnsulmh.png-25.5kB][26]

#### x64
 
 - RBP 不再用作栈帧指针
 - 每个模块的 Windows 符号文件（.pdb）包含对镜像栈跟踪的必要信息
     - 在 Bochspwn 加载符号用于符号化虚拟地址
 - Debug Help Library 中的 StackWalk64 执行函数
     - 要求关于目标 CPU 内容的多个原语和信息，这些在 Bochs 中都容易获得

![image_1cios61mp13pb18ajsbr149r1rnvne.png-114kB][27]

示例：THREAD_BASIC_INFORMATION
![image_1cip1c0201ak7lti12b61fkr55or.png-75.4kB][28]

示例：MEMORY_BASIC_INFORMATION
![image_1cip1g4t1ge4f3d7as1lh71va2p8.png-82kB][29]

示例：MOUSEHOOKSTRUCTEX
![image_1cip1h5u9h6ujmp144trck1uuepl.png-72.4kB][30]

17个新的 x64 信息泄露
![image_1cip1l8nu160q1hr7i4814abikrq2.png-160.8kB][31]

## 在文件系统中检测内存泄漏
### 检测

 - 在 Bochs 中插桩，用可识别的字节填充全部栈/堆分配
 - 更改 Bochs 的磁盘操作模式由 flat 为 volatile
 - 启动操作系统，执行文件系统相关操作
 - 用可识别字节定期扫描磁盘更改日志

### 结果（Windows）

 - FAT
 - FAT32
 - exFAT

在 NTFS 中的适度泄漏
![image_1cip2h27u107ktcj88hgglb0uqf.png-65.1kB][32]

## 通过 double-writes 识别 KASLR 绕过
double write 竞态条件
![image_1cip30fuq16jrcpa18kbbhrb0iqs.png-58.7kB][33]
double write 利用
![image_1cip35qo4bf5p3muqk4dr1oi7r9.png-70kB][34]

![image_1cip3f9bu12m0q8lkd01rt9hoirm.png-42.8kB][35]
![image_1cip3g2fikr29h91ckf1nfgt5csj.png-35.9kB][36]

### 情况

 - 用户/内核模式间传递的、带有指针的典型结构
    - 类似于未初始化的内存泄漏
    - 它更容易复制整个结构体和调整特定领域，之后单独拷贝每个字段或构建一个额外的本地对象
 - copy_to_user 编写更安全的代码
     - 如果直接的指针操作不被允许，那对象的本地副本就更有可能被创建

### 系统插桩检测

 - 通过 bx_instr_lin_access 记录所有内核到用户的内存写操作
 - 如果该操作覆写了被写在相同线程/系统调用范围内的非零数据，就报告 bug
     - 当内核态地址被用户态地址覆写的时候发送 signal

double write bug report
![image_1cip4veialgkma5fn47919t0.png-143.8kB][37]

### 结果

 - nt!IopQueryNameInternal
    - 结构体：UNICODE_STRING
    - 通过几个入口点，例如：nt!NtQueryObject、nt!NtQueryVirtualMemory
 - nt!PspCopyAndFixupParameters
    - 结构体：RTL_PROCESS_PARAMETERS 中的 UNICODE_STRING
 - win32k!NtUserfnINOUTNCCALCSIZE
    - 结构体：NCCALCSIZE_PARAMS

## PDB 文件内存泄露（CVE-2018-1037）
### 准备 Windows 符号

 - 每个新的 Bochspwn 之前，我下载了目标系统文件对应的 .pdb 文件
 - 随机检查了 Windows 10 中的 combase.pdb 的内容，我注意到文件头中的 3kb 奇怪数据

![image_1cip5huvf15r6ugq1f6i1ti01ievtd.png-463.8kB][38]

### VS 中的 PDB 生成

 - 在 Visual Studio 中，mspdbcore.dll 用于生成符号文件
    - 外部的、长期的 mspdbsrv.exe 进程托管
 - 该库的源代码由微软发布在 GitHub 上的 microsoft-pdb 仓库
    - 可以自由地审计

### PDB 结构

 - 基本的 MSF（Multi-Stream Format）文件
    - 分割成指定大小的块/页（512/1024/2048/4096）
    - 在 Visual Studio 中典型的大小是 1024/4096 字节
 - 第一个块在偏移为 0 处是 super block（或 MSF 头）

![image_1cip623ei2sba0781f1e9l6t0ua.png-20.8kB][39]

### 头结构

![image_1cip62tb2199cv0b1gko15etjndun.png-57kB][40]

### 创建 PDB

![image_1cip63oskmtf18vh1dplouvn57v4.png-70.3kB][41]

### 更新显存 PDB

![image_1cip64kss14hv90ccui1eh71d82vh.png-92.3kB][42]

### Bug
![image_1cip65apu1qs31082et7rpvnf9vu.png-43.1kB][43]

### 泄露范围

 - PDB 文件不常在互联网上交换，除了 Microsoft Symbol Server
 - 分析一下问题的严重性！
    - 只有 Windows 10 符号受影响
    - 只有一小部分的 .pdb 文件包含泄露
    - 通过检查 cbPg=4096 很容易检查

### 受影响的文件
![image_1cip6a8vj107i1t2vp5p85p1g9j11e.png-132.8kB][44]

### 泄露范围
![image_1cip6alfg11m5rgfpkoaa6pf11r.png-76.8kB][45]

## 未来工作与结论

两周前修复的
![image_1cip6c3h2mda7kjreltvf79128.png-114.4kB][46]

### PDBCopy 工具更新
用法：
```
PDBCOPY.exe <target.pdb> <backup.pdb> -CVE-2018-1037 {[verbose|autofix]}
```
参数：

 - target.pdb：要升级的 PDB 文件名
 - backup.pdb：备份 PDB 文件的文件名
 - CVE-2018-1037：判断 PDB 文件是否受该问题影响

### 限制
动态二进制插桩的典型缺点：

 - 性能
 - 依赖于内核代码覆盖率
 - 不能测试大多数设备驱动
 - 污点跟踪的精确度

### 未来工作

 - 其他操作系统
 - 其他数据：文件系统、网络
 - 其他安全域：进程间通信（沙盒）、虚拟化


  [1]: http://static.zybuluo.com/Titan/dhke6aqpiv2z0gvgqvjl18cs/image_1cio36kmj1oqm11eq1954dp10699.png
  [2]: http://static.zybuluo.com/Titan/6qip0sx4kny9nlfh9ojg4br1/image_1cio5ed1c15p01okkgsp80kkph16.png
  [3]: http://static.zybuluo.com/Titan/zdwlygavdt5a0zpzac7u6rjn/image_1cio7r26jvsgtlba7v1fl6mkq1j.png
  [4]: http://static.zybuluo.com/Titan/5j8qxx25ni1s7toog4bc1gqy/image_1cio8amkr1km7pnkbmkuep1fh053.png
  [5]: http://static.zybuluo.com/Titan/5hh3k4ab6haomgnlwci7v8ee/image_1cio8d609e3omd1165n1ga9suf5g.png
  [6]: http://static.zybuluo.com/Titan/moz83wgt1t55p17lzjanbhhh/image_1cio8em0q157mrmv39r1ruq1tdt6d.png
  [7]: http://static.zybuluo.com/Titan/pqllcrroarr99a2t9twdk4oo/image_1cio8jqb3tn11v2fqoj1g01aih9d.png
  [8]: http://static.zybuluo.com/Titan/xch36jgpdxckrcjquuwpunjg/image_1cio8l6ipo63khv1sgu16fh154o9q.png
  [9]: http://static.zybuluo.com/Titan/c3rwd8neemxpbriw9uef6mil/image_1cio8mhf313ks8hn1p6t56df8da7.png
  [10]: http://static.zybuluo.com/Titan/cnnkr3xdbprikpgjatt3h031/image_1cio994vr19otom11beqgt1apbak.png
  [11]: http://static.zybuluo.com/Titan/heq8yy74ynctynkb1he8nhha/image_1cio9e06lb4a5vllc61c4o1jq4ch.png
  [12]: http://static.zybuluo.com/Titan/0r53zqsx2osrw7k8vrjbtcwg/image_1cio9eu8fd9t15uc42de6p1htpcu.png
  [13]: http://static.zybuluo.com/Titan/vnoocmxea8xln7fmwicrofq5/image_1cio9g6oo1i86148u350l5d1cufeb.png
  [14]: http://static.zybuluo.com/Titan/od8ki5w668vh19s72aw7bmiu/image_1cio9gg8c9lad5v1rlk7i81t4reo.png
  [15]: http://static.zybuluo.com/Titan/9r12wxeyxgixx3luzr44ttbm/image_1cio9mgrl2mihs9deohju1j7jhl.png
  [16]: http://static.zybuluo.com/Titan/cbjbicisc6qcvqqactoexa3k/image_1cio9p6o51d9cgsr183hbsln1ai2.png
  [17]: http://static.zybuluo.com/Titan/lc41d19kn8iqy1jwpel6u0o2/image_1cio9rt441cu8bbtccqu5g2a5is.png
  [18]: http://static.zybuluo.com/Titan/fv28rfmvd70igzx9qgo9e2mb/image_1cioa73if7ug1fe3annum51ajnj9.png
  [19]: http://static.zybuluo.com/Titan/913eav90hxlyk1id3g49e6l1/image_1cioa7g5qeph1q741g5e17ml1u7ljm.png
  [20]: http://static.zybuluo.com/Titan/q4ay0tmvh24qmk2b520lbg25/image_1ciof688a9sunfn1t8714q910m6k3.png
  [21]: http://static.zybuluo.com/Titan/qa54k6g2cr2feij06bquzz2m/image_1ciof6pknrcg1cc81n811ctjpdnkg.png
  [22]: http://static.zybuluo.com/Titan/8b6runsecb06qw2zvjyt1cgm/image_1ciog1dr31vt9136n1mp61d8jf3kkt.png
  [23]: http://static.zybuluo.com/Titan/busmv2zs2ycx61x23e048fj9/image_1ciog325s19l51t29od43td99jla.png
  [24]: http://static.zybuluo.com/Titan/wgz405wnezc85cdfrm8y3fsx/image_1ciog70dpnqks9pllo1chlroeln.png
  [25]: http://static.zybuluo.com/Titan/4haa3todevmlhwu4j8niqy2f/image_1ciog9bhp5f611ic1i8rdnqcm0m4.png
  [26]: http://static.zybuluo.com/Titan/er23dl9gawz6jo0lvp8c94du/image_1cioh2rdemvl12oj3bmcnnsulmh.png
  [27]: http://static.zybuluo.com/Titan/1p2pg64904fezehbv4td69ms/image_1cios61mp13pb18ajsbr149r1rnvne.png
  [28]: http://static.zybuluo.com/Titan/jyyc9sclmamj7pwf2u1prmvj/image_1cip1c0201ak7lti12b61fkr55or.png
  [29]: http://static.zybuluo.com/Titan/mum1dmlha7a4gtisf2ht72fk/image_1cip1g4t1ge4f3d7as1lh71va2p8.png
  [30]: http://static.zybuluo.com/Titan/dkt229702w0vq4dzd9k6rqry/image_1cip1h5u9h6ujmp144trck1uuepl.png
  [31]: http://static.zybuluo.com/Titan/75ksai5sxss0i60ef0cd2ww6/image_1cip1l8nu160q1hr7i4814abikrq2.png
  [32]: http://static.zybuluo.com/Titan/sz3mzsvb7nbvzijbqgv8w7xc/image_1cip2h27u107ktcj88hgglb0uqf.png
  [33]: http://static.zybuluo.com/Titan/kdmnej621k0pksd50nfbzj7s/image_1cip30fuq16jrcpa18kbbhrb0iqs.png
  [34]: http://static.zybuluo.com/Titan/r3garm9usgsf6kdvckv6gfoq/image_1cip35qo4bf5p3muqk4dr1oi7r9.png
  [35]: http://static.zybuluo.com/Titan/vhn96ehoufv61ruayv2evo6b/image_1cip3f9bu12m0q8lkd01rt9hoirm.png
  [36]: http://static.zybuluo.com/Titan/u7lmjd15wm1hk6tuccg4vpih/image_1cip3g2fikr29h91ckf1nfgt5csj.png
  [37]: http://static.zybuluo.com/Titan/lt6izrr7wzfqjnwvdgnf3dfa/image_1cip4veialgkma5fn47919t0.png
  [38]: http://static.zybuluo.com/Titan/w3bc58vl17ht5yv55y8e5yvx/image_1cip5huvf15r6ugq1f6i1ti01ievtd.png
  [39]: http://static.zybuluo.com/Titan/7grig19eiodac9bcwxxjwz2p/image_1cip623ei2sba0781f1e9l6t0ua.png
  [40]: http://static.zybuluo.com/Titan/izgyx1a9b12p9ybnpvnq5qam/image_1cip62tb2199cv0b1gko15etjndun.png
  [41]: http://static.zybuluo.com/Titan/imit3936gi3wj590wcn7av1q/image_1cip63oskmtf18vh1dplouvn57v4.png
  [42]: http://static.zybuluo.com/Titan/3okj97polinna4x0k9nk8jzg/image_1cip64kss14hv90ccui1eh71d82vh.png
  [43]: http://static.zybuluo.com/Titan/hefovu7d7eaps8iir65mbf2o/image_1cip65apu1qs31082et7rpvnf9vu.png
  [44]: http://static.zybuluo.com/Titan/gkr8flo1pra9ue9qyk5haqh2/image_1cip6a8vj107i1t2vp5p85p1g9j11e.png
  [45]: http://static.zybuluo.com/Titan/puci69ngmg6sin1055k5effn/image_1cip6alfg11m5rgfpkoaa6pf11r.png
  [46]: http://static.zybuluo.com/Titan/1bynopiycxbwpmkg0dmkvzvk/image_1cip6c3h2mda7kjreltvf79128.png
# Syzkaller 介绍


标签（空格分隔）： Fuzzing

---

## 三个基石
### Kernel Sanitizers (KASAN, KMSAN, KTSAM)
快速且全面的 UAF 和 OOB 解决方案
 - 基于编译时插桩
 - 检测 OOB 写与 OOB 读
 - 检测堆、栈、全局变量中的 OOB
 - 强 UAF 检查
 - Double-Free 检查
 - 检测 Bug 的发生位置
 - 打印翔实的相关信息
 
Upstream:CONFIG_KASAN + GCC 5.0+
 
KASAN Report (CVE-2013-7446) 

![image_1chpc22p7bb1pqmce4102a1bvb3a.png-82.2kB][1]
 
### KMSAN (KernelMemorySanitizer)
检测未初始化的内存、信息泄露（本地与远程）
not loads of not-stored-to variables, but uses of uninitialized values (see backup)
往往不加载未存储的变量，而是使用未初始化的值
没有误报，几乎没有漏报
 
Not upstreamed yet(on github): CONFIG_KMSAN + Clang

![image_1chpc2hol17ga1r4ukecbm11sre3n.png-96.1kB][2]
 
### KTSAN (KernelThreadSanitizer)
检测数据竞态（不同线程中的两个非同步访问，至少一个是 write）
内核数据竞态代表安全威胁：
 - TOCTOU
 - 未初始化/错误 Credentials
 - racy UAF
 - 由数据竞态造成的 Double Free
 - Bug 最频繁的类型
 
KTSAN Report (CVE-2015-7613)

![image_1chpc2p3u1qba1kanh07nkq1l7244.png-95.8kB][3]
 
fuzzing + sanitizers = perfect fit!
 
## 现存的 Fuzzer
trinity/iknowthis in essence:

![image_1chpc3a0k1pv63u1qfgqtf19fs4h.png-8.6kB][4]

知道参数类型，更像

![image_1chpc3er31u5ev8bujjp5b8e4u.png-9.7kB][5]

### 缺点

 - 倾向于找到 Shallow Bug
 - frequently no reproducers
 - 不适合回归测试
 
## 覆盖度指导的 Fuzzing

 - 代码覆盖度指导
    - Interesting 样本的语料
    - 语料库中样本的畸变和执行
    - 如果样本触发了新的代码覆盖度就添加到语料库
 - 优势
    - 将指数问题转化为线性
    - 输入样本是 reproducers
    - 语料库是回归测试的理想工具
 
### 内核代码覆盖度

 - CONFIG_KCOV=y (upstream)
 - 基于编译时插桩（GCC 6+）
 - 编译时为每个基本块插入运行时回调函数
 - 每个线程、每个系统调用的覆盖度
 
## 系统调用描述
所有系统调用的声明性描述

![image_1chpc3va2fi61rdi9ga170u16e95b.png-41.2kB][6]

### 程序
这些描述允许程序按照以下形式进行生成、畸变

![image_1chpc486u8sq15lagmn1aul9f95o.png-28.4kB][7]

### 算法

![image_1chpc4dij1o735raiba1l3a171b65.png-61.5kB][8]
 
## Operational side
理想中

![image_1chpc4j9l60hbq2o7rmmq1g2q6i.png-10.3kB][9]

实际上，典型内核 Fuzzer 的操作：

 - 手动创建虚拟机
 - 手动拷贝、启动二进制程序
 - 手动监控控制台输出
 - 手动崩溃去重
 - 手动定位与重现
 - 手动重启崩溃虚拟机
 
Syzkaller 的操作

![image_1chpc4tihv5e10881gts1r5kqcu6v.png-58.1kB][10]

### 测试机
当前支持：

 - QEMU
 - GCE（Google Compute Engine）
 - Android Devices（with serial cable / Suzy-Q）
 - ODROID boards

可扩展的、需要支持的新类型：

 - 得到控制台输出（to grep for crashes）
 - 重新启动、重新创建（to repair after a  crash）
 - 拷贝、运行二进制程序（think of scp/ssh）
 
## 教程
### 设置 syzkaller

 - 用稍特殊的方式构建内核
 - 构建 syzkaller
 - 写配置文件
 - 运行 syzkaller
 
### 内核构建

![image_1chpc5spb1p1m86hvkn1dv81nng7c.png-81.7kB][11]

### syzkaller 构建

![image_1chpc62bn1jcu1ts9ket1nofjr57p.png-47.9kB][12]

### Syzkaller 为 QEMU 的配置

![image_1chpc693couo10e91lel12d7k8486.png-67.3kB][13]

![image_1chpc6dqa1q81pmcf0m57j10nh8j.png-66.2kB][14]

![image_1chpc6iik17it147b1ckb1oco1c3d90.png-67.3kB][15]

![image_1chpc6nrrock14ud1sar1hhkbl9d.png-71.1kB][16]

![image_1chpc6t4rr9i16o8cf832n98t9q.png-73.3kB][17]

![image_1chpc72m01tebu2ei93813t99a7.png-72.1kB][18]

![image_1chpc7869gv11q20194p5ghjknak.png-78.2kB][19]
 
### Syzkaller 为 Android 的配置
![image_1chpc7hr41dv2gi65op1l7p1pe5b1.png-66.9kB][20]
 
Ready to go
$ bin/syz-manager -config my.cfg
 
### 扩展到面向新驱动
如何在 Android 上 fuzzing /dev/ion
1、为描述创建新文件 sys/ion.txt
2、为新系统调用写描述
3、重新构建
4、运行
 
sys/ion.txt : includes

![image_1chpc80q013d12ml33t13lg1ebsbe.png-55.4kB][21]

sys/ion.txt resources

![image_1chpc86e318ktgctj1j1gfn1tonbr.png-59.4kB][22]

sys/ion.txt system calls

![image_1chpc8b5e107b4isbnvdodgk4c8.png-100.9kB][23]

sys/ion.txt structs

![image_1chpc8guk1qru1ugd11mcfn11bu4cl.png-40.3kB][24]
 
重新构建

![image_1chpc8u0pf80ne17tmvfu1piad2.png-66.8kB][25]

sys.ion_arm64.const

![image_1chpc95qn1c81g4f7r5k301kf2df.png-70.5kB][26]
 
$ bin/syz-manager -config my.cfg
 
## 我们团队的动态测试工具
用户态工具：ASAN、MSAN、TSAN
内核态工具：KASAN、KMSAN、KTSAN
Hardening：CFI、SafeStack
Fuzzing：LibFuzzer、syzkaller、OSS-Fuzz


  [1]: http://static.zybuluo.com/Titan/y2di6n7nm1p633ln6o8pu9jf/image_1chpc22p7bb1pqmce4102a1bvb3a.png
  [2]: http://static.zybuluo.com/Titan/ks9aezbyy06mwdk5n6sc1trv/image_1chpc2hol17ga1r4ukecbm11sre3n.png
  [3]: http://static.zybuluo.com/Titan/cyg39np5oostagmt1l0nuj85/image_1chpc2p3u1qba1kanh07nkq1l7244.png
  [4]: http://static.zybuluo.com/Titan/46ubgd7yb423el7b67s6mhy7/image_1chpc3a0k1pv63u1qfgqtf19fs4h.png
  [5]: http://static.zybuluo.com/Titan/wsey5c28du2cl3qnqjssguzy/image_1chpc3er31u5ev8bujjp5b8e4u.png
  [6]: http://static.zybuluo.com/Titan/v5vlyfc66ux16357pl40zgy5/image_1chpc3va2fi61rdi9ga170u16e95b.png
  [7]: http://static.zybuluo.com/Titan/afpw6gflezaa6se3rdfoui1v/image_1chpc486u8sq15lagmn1aul9f95o.png
  [8]: http://static.zybuluo.com/Titan/4lm5r1ggxe5j5l9oip77q3is/image_1chpc4dij1o735raiba1l3a171b65.png
  [9]: http://static.zybuluo.com/Titan/zuubo0izdxhy1rrd5i58038h/image_1chpc4j9l60hbq2o7rmmq1g2q6i.png
  [10]: http://static.zybuluo.com/Titan/mj9jxxig0ci49rfgt0fojq91/image_1chpc4tihv5e10881gts1r5kqcu6v.png
  [11]: http://static.zybuluo.com/Titan/pad8cjg65i5y9f0hpfn728gz/image_1chpc5spb1p1m86hvkn1dv81nng7c.png
  [12]: http://static.zybuluo.com/Titan/cgyan7ig5ceuqkcbnx5mgdl2/image_1chpc62bn1jcu1ts9ket1nofjr57p.png
  [13]: http://static.zybuluo.com/Titan/15w9llx4dp0inldp48amy1ln/image_1chpc693couo10e91lel12d7k8486.png
  [14]: http://static.zybuluo.com/Titan/mmzok1p1j0i7b2l3r2c5m2oo/image_1chpc6dqa1q81pmcf0m57j10nh8j.png
  [15]: http://static.zybuluo.com/Titan/wpay8kxam68kdcl0b9hp3olq/image_1chpc6iik17it147b1ckb1oco1c3d90.png
  [16]: http://static.zybuluo.com/Titan/e1w6lyax1mrs5m8t4wp8c457/image_1chpc6nrrock14ud1sar1hhkbl9d.png
  [17]: http://static.zybuluo.com/Titan/r1vw5o8rzak6ypyj5rye7qxj/image_1chpc6t4rr9i16o8cf832n98t9q.png
  [18]: http://static.zybuluo.com/Titan/k4sr935xe5umvhtfn4ny5ri4/image_1chpc72m01tebu2ei93813t99a7.png
  [19]: http://static.zybuluo.com/Titan/kccww8ahxujo55pw3csdgehm/image_1chpc7869gv11q20194p5ghjknak.png
  [20]: http://static.zybuluo.com/Titan/0qwx43chor0t1wbnhboxm80p/image_1chpc7hr41dv2gi65op1l7p1pe5b1.png
  [21]: http://static.zybuluo.com/Titan/phn6m9clzfup8iz9pe40g20g/image_1chpc80q013d12ml33t13lg1ebsbe.png
  [22]: http://static.zybuluo.com/Titan/vwc91f0uiavl0jne3sbewokt/image_1chpc86e318ktgctj1j1gfn1tonbr.png
  [23]: http://static.zybuluo.com/Titan/0d7i48m8za2q1xdphrrswxlz/image_1chpc8b5e107b4isbnvdodgk4c8.png
  [24]: http://static.zybuluo.com/Titan/epbuqzu8i5vh0gl1fr7v3c7w/image_1chpc8guk1qru1ugd11mcfn11bu4cl.png
  [25]: http://static.zybuluo.com/Titan/qywzq27mavxt2lc394878czl/image_1chpc8u0pf80ne17tmvfu1piad2.png
  [26]: http://static.zybuluo.com/Titan/5y9b84aok9d54j8ph0hl246m/image_1chpc95qn1c81g4f7r5k301kf2df.png
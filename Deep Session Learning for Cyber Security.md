# Deep Session Learning for Cyber Security

标签（空格分隔）： Paper

---

## 论文摘要
Lab41 提出了将深度学习应用于 SDN 环境中的一个方案，并实现了名为 [Poseidon][1] 的原型系统。该系统主要有三大目标：

 - 应用深度学习于网络数据包中
 - 配置于 SDN 环境中
 - 使用微服务架构将前两者连通

该方案设计主要解决两个疑惑：

 - 网络上有什么
 - 它们在干什么

## 工作背景
网络数据包中几乎全部都是正常的流量数据包，仅有极少量的数据包是异常/恶意流量。在这种极不平衡的分类问题中构建分类器是极其困难的，因为分类器会简单地得出一个结论：“所有的内容都将被标记为正常，同时产生 99.99999% 的精确度”

一些年前，伯克利和劳伦斯-伯克利国家实验室发布了一篇将机器学习应用于 IDS 的论文。现实生活中的流量千变万化远远超出了人们的预期，这导致了异常检测技术在实际环境中的一系列问题

通过建模发现网络中的异常是困难的，可能会有较高的误报率。从而将异常检测问题转化为分类问题

两台计算机间传递的所有数据包的集合被称为会话（Session），深度包检测的方法会带来其他问题，如计算时间、加密等

不仅包内需要有序组织，包间（会话内）也有序组织，为深度学习提供良好的样本，创建异常会话分类器

从异常检测到分类识别的好处是可编程构造异常。最近兴起的生成式对抗网络（GAN），其中竞争神经网络用于生成与训练训练集有区分度的样本

## 工作设计

本文采用三个基本技术生成异常会话：

 - 交换源地址与目的地址的 IP 与 MAC 地址
 - 交换端口号
 - 保留源 IP 地址，用从未与之通信过的 IP 地址与目的地址交换

模拟生成的会话应该在网络中几乎不发生。每个会话在训练时都有 50% 的机会保留为一个正常的会话，50% 的机会变异为三种异常会话之一

因为包头的十六进制和会话中的包头都有良好的顺序，RNN 是编码的自然选择

使用了两个 RNN：

 - 一个用来提取包头的十六进制
 - 一个用来编码会话中的所有数据包

![image_1c87qsdf51dap1j171moj1km11lt19.png-57.4kB][2]

输出包头中所有信息的“摘要”，而后收集这些代表包的数据并使用其创建代表会话的数据包，最后得到代表整个会话的实值向量

![image_1c87qtgffr671bb917bp1rti71sm.png-62.4kB][3]

为了忽略不那么重要的部分，强调更重要的部分，需要添加权重：

 - 数据包更加关注包头
 - 会话更加关注起始数据包

一个会话抽取前八个包

![image_1c87qtq1s9eq8j71v5b18qtav713.png-61.4kB][4]

深蓝表示数据包更关注的内容，深红表示会话更关注的内容

重要的内容段可以进一步参阅[其他文章][5]，特别是[这一个][6]

## 工作评估
使用 2012 年 New Brunswick 的 IDS 数据集，包含七天的 PCAP 文件。只使用前三天的数据，前两天的数据用于训练模型，捕获率 83.8%，误报 0.5%


## 结论与思考
模型不能识别已在本地的恶意行为，但一旦试图通过网络进行传输就会发现

模型的成功表明会话中的起始数据包在复杂网络攻击中的重要性


  [1]: https://github.com/CyberReboot/poseidon
  [2]: http://static.zybuluo.com/Titan/oj6i0mke85es6fldtqjaib1r/image_1c87qsdf51dap1j171moj1km11lt19.png
  [3]: http://static.zybuluo.com/Titan/y07t466d5lghzw8vl24qrp2w/image_1c87qtgffr671bb917bp1rti71sm.png
  [4]: http://static.zybuluo.com/Titan/961wotohbzqxbz5bltkaj96b/image_1c87qtq1s9eq8j71v5b18qtav713.png
  [5]: http://distill.pub/2016/augmented-rnns/?utm_campaign=Revue%20newsletter&utm_medium=Newsletter&utm_source=revue
  [6]: https://devblogs.nvidia.com/parallelforall/introduction-neural-machine-translation-gpus-part-3/
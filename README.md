# Simple Ping - ICMP实验程序

## 项目简介

这是一个基于ICMP协议的简单ping程序实现，支持IPv4和IPv6。本程序整合了三个ping程序的功能，提供了完整的网络诊断和测试工具。

## 主要特性

- 支持IPv4和IPv6协议
- 基本的ICMP echo请求和回复处理
- RTT（往返时间）计算和显示，支持高精度模式
- 丰富的配置选项和功能
- 时间戳显示功能
- 多种网络诊断功能

## 编译和运行

### 编译

```bash
make
```

### 运行

```bash
# 需要root权限运行（因为使用原始套接字）
sudo ./ping hostname
sudo ./ping -v hostname  # 详细模式
sudo ./ping -V            # 显示版本信息
```

## 使用方法

```
Usage: ping [options] <hostname>
```

## 命令行选项

### 基础选项

- `-b`: 允许ping广播地址
- `-c count`: 发送指定数量的包后停止
- `-h`: 显示帮助信息
- `-i interval`: 设置包发送间隔（秒，默认1秒）
- `-q`: 安静模式，仅显示汇总统计
- `-s size`: 设置数据包大小（字节数）
- `-t ttl`: 设置IP TTL值（1-255）
- `-v`: 详细输出模式
- `-W timeout`: 设置回复等待超时时间（秒，默认1秒）

### 协议选项

- `-4`: 强制使用IPv4
- `-6`: 强制使用IPv6

### 高级选项

- `-d`: 启用SO_DEBUG套接字调试模式
- `-m mark`: 设置包标记值
- `-M pmtudisc`: 路径MTU发现模式（do/dont/want/probe）
- `-I interface`: 指定网络接口或IP地址
- `-T tstamp`: 时间戳选项（tsonly/tsandaddr/tsprespec）
- `-f`: 洪水ping模式（需要root权限）
- `-n`: 数字输出模式（不解析主机名）
- `-p pattern`: 使用十六进制模式填充数据包
- `-r`: 绕过路由表
- `-R`: 记录路由（IPv4）
- `-l preload`: 预加载模式（需要root权限）
- `-w deadline`: 设置运行时间限制（秒）

### 新增选项

- `-V`: 打印版本信息并退出
- `-3`: RTT高精度模式（不对结果时间进行四舍五入）
- `-D`: 打印时间戳
- `-S size`: 设置SO_SNDBUF套接字选项值

## 使用示例

### 基础用法

```bash
# 基本ping
sudo ./ping google.com

# 发送5个包
sudo ./ping -c 5 google.com

# 详细模式
sudo ./ping -v google.com

# 安静模式
sudo ./ping -q -c 10 google.com
```

### 高级用法

```bash
# 高精度RTT测量
sudo ./ping -3 google.com

# 带时间戳的ping
sudo ./ping -D google.com

# 设置发送缓冲区大小
sudo ./ping -S 8192 google.com

# 强制IPv4，设置TTL
sudo ./ping -4 -t 64 google.com

# 数字输出模式，不解析主机名
sudo ./ping -n 8.8.8.8

# 记录路由
sudo ./ping -R google.com

# 设置包大小和间隔
sudo ./ping -s 1000 -i 0.5 google.com
```

### 网络诊断

```bash
# 广播ping
sudo ./ping -b 192.168.1.255

# 绕过路由表
sudo ./ping -r 192.168.1.1

# 洪水测试（谨慎使用）
sudo ./ping -f -c 100 target.com

# 使用特定接口
sudo ./ping -I eth0 google.com
```

## 输出格式

### 标准输出
```
ping google.com (142.250.191.14): 56 data bytes
64 bytes from 142.250.191.14: seq=0, ttl=117, rtt=15.234 ms
64 bytes from 142.250.191.14: seq=1, ttl=117, rtt=14.891 ms
--- google.com ping statistics ---
2 packets transmitted, 2 received, 0.0% packet loss, time 1.001 s
```

### 高精度模式（-3）
```
64 bytes from 142.250.191.14: seq=0, ttl=117, rtt=15.234567 ms
```

### 带时间戳模式（-D）
```
[14:30:15.123456] 64 bytes from 142.250.191.14: seq=0, ttl=117, rtt=15.234 ms
```

## 版本信息

当前版本：1.0.0

查看版本：
```bash
./ping -V
```

## 注意事项

1. **权限要求**：由于使用原始套接字，程序需要root权限运行
2. **洪水模式**：`-f` 选项可能对网络造成压力，请谨慎使用
3. **预加载模式**：`-l` 选项需要root权限
4. **广播ping**：某些网络设备可能不响应广播ping
5. **IPv6支持**：确保系统支持IPv6网络

## 技术特性

- 支持IPv4和IPv6双栈
- 精确的RTT计算
- 完整的ICMP协议处理
- 灵活的网络诊断选项
- 兼容标准ping程序的主要功能

## 许可证

本程序为自由软件，遵循开源许可证。

## 贡献

欢迎提交bug报告和功能请求。
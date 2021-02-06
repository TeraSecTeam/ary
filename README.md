# Ary

![x](./doc/ARY.png)

Ary 是一个集成类工具，主要用于调用各种安全工具，从而形成便捷的一键式渗透。

![](https://img.shields.io/github/stars/TeraSecTeam/ary?style=flat-square) ![](https://img.shields.io/github/downloads/TeraSecTeam/ary/total?style=flat-square)
 
> 版本：2.1.1  公开版
>
> 作者： Ali0th
>
> 联系： martin2877@foxmail.com
>
> 主页： github.com/Martin2877
>
> 声明：本工具仅供学习、测试使用，严禁用于非法用途，开发者对使用者的违法行为不负责任。
>
> 交流：欢迎提issue，或私信我加入工具使用交流群。

## 下载

[前往releases下载](https://github.com/TeraSecTeam/ary/releases/)

## 相关文档

[我的一键 getshell 代码开发之路v1.8.pdf](./doc/我的一键getshell代码开发之路v1.8.pdf)


## 功能

> 注意，部分功能还在开发中

0. 信息收集工具(开发中)
1. 通过多个网络空间的搜索引擎批量爬取相应网站, 如 Fofa, shodan, censys
2. 通过资产识别工具探测，如 ARL, Rad, crawlgo, gospider
3. 非指向性漏扫工具， 如 xray,AWVS, (MSF 开发中)
4. 通过 PoC 工具验证漏洞,目前已支持 pocsuite3 python, xray yaml 两种形式的 poc
5. webshell 管理工具批量 getshell, 如 CobaltStrike, antsword (此模块开发中)
6. 录包工具
7. 执行流
8. 流量检测规则编写与测试，如 suricata 规则编写

## 自动挖洞思路

```bash
1. 漏扫法1-直接扫：
1) 采集域名，越多越好
2) 针对域名集合进行扫描，直接调用 xray 或 awvs 等工具进行漏扫。

2. 漏扫法2-先信息收集后扫：
1) 针对域名集合进行扫描
2) 针对域名全部调用 ARL 进行子域名爬取
3) 调用 ARL 中的全部子域名，进行漏洞扫描
4) 调用 xray 或 awvs 等工具进行漏扫

3. PoC扫全网法：
1) 已有 PoC 和查询指纹，通过查询收集域名或IP，然后 PoC 验证漏洞。
2) 定时器，定时进行执行任务
```

## 开发理念

1. 尽量使用 golang 写的工具，方便直接调用可执行文件，就不需要重构第三方工具
2. 尽量使用 pip 安装的模块，并使用 python api 进行调用，方便简单
3. 有些需要独立环境的工具，尽量使用 docker 来启动，并使用 API 来交互

## 环境

主要运行环境：centos，其它环境未测试 

## 安装

1.安装所有的工具引擎：

```bash
# 更新所有引擎，如果存在则不更新
./ary --manager --update -v

# 强制更新所有引擎
./ary --manager --update --force -v  

# 根据各个模块去更新引擎
./ary --assertscan --engine all --update -v
./ary --vulnscan --engine all --update -v

# 更新 PoC 
./ary --pocscan --update --keyword poc -v
```

2.chrome 的安装(爬虫需要)

配置yum：vi /etc/yum.repos.d/google.repo

```bash
[google]
name=Google-x86_64
baseurl=http://dl.google.com/linux/rpm/stable/x86_64
enabled=1
gpgcheck=0                                                                                                                                     
gpgkey=https://dl-ssl.google.com/linux/linux_signing_key.pub
```

```bash
yum update
yum install google-chrome-stable
google-chrome --version
```

3.docker 的安装(容器需要)

```bash
yum install docker -y
service docker start
```


## 使用

使用 `-h` 能够自动生成所有相关的目录和文件。

```bash
./ary -h
```

1. `REAME.md` 文件能够自动生成。

2. 在任何情况下，使用 `-v` 能够查看debug详情。

3. `/onfigs/settings.ini` 为主要的配置文件，使用网络空间搜索需要在其中配置凭证。

4. `streams.yaml` 为执行流文件，相关执行流在这其中配置。

### docker 控制

```bash
# 需要使用 awvs 时启用
./ary --docker --action start --engine awvs -v
./ary --docker --action stop --engine awvs -v
./ary --docker --action remove --engine awvs -v

# 需要测试 suricata 时启用
./ary --docker --action start --engine suricata -v
./ary --docker --action stop --engine suricata -v
./ary --docker --action remove --engine suricata -v
```

### 网络空间搜索

```bash
./ary --netsearch --engine shodan --keyword dedecms -v --limit 10
./ary --netsearch --engine shodan --keyword "tomcat country:\"US\"" -v --limit 10

./ary --netsearch --engine fofa --keyword redis -v --limit 10
./ary --netsearch --engine fofa --keyword "protocol=socks4 && banner=\"0x5a\"" -v --limit 10

./ary --netsearch --engine censys --keyword redis -v --limit 1000
```

### 资产扫描

ARL:

```bash
# 启动一个任务
# 查找子域名
./ary --assertscan --engine arl --url www.aaa.com -v --condition subdomain
./ary --assertscan --engine arl --url www.aaa.com,www.bbb.com -v --condition subdomain
# 查找子域名 指定文件
./ary --assertscan --engine arl --input targets.txt -v --condition subdomain
# 查找子域名 指定输出文件名
./ary --assertscan --engine arl --url www.aaa.com -v --condition subdomain --output arl.csv

# 查找端口
./ary --assertscan --engine arl --input targets.txt -v --condition portscan

# 获取任务结果
./ary --assertscan --engine arl -v --fetch-result --keyword 5fd321f0a4a557000fb2a574
# 获取任务结果 - 加载文件
./ary --assertscan --engine arl -v --fetch-result --input arl.csv
```

爬虫类：

```bash
# 爬虫类
./ary --assertscan --engine rad --url http://testphp.vulnweb.com/ -v

./ary --assertscan --engine gospider --url http://testphp.vulnweb.com/ -v

./ary --assertscan --engine crawlergo --url http://testphp.vulnweb.com/ -v
```

AWVS:

```bash
# 使用 awvs 进行爬虫，并保存到 txt 文件，不等待
./ary --vulnscan --engine awvs --url testphp.vulnweb.com -v --crawl

# 使用 awvs 进行漏洞扫描
./ary --vulnscan --engine awvs --url testphp.vulnweb.com -v

# 获取 awvs 结果(状态)
./ary --vulnscan --engine awvs --fetch-result --keyword 4704d46c-908a-4c2d-85bf-a615cc396d49 -v
```

### 漏洞扫描：

```bash
# 对目标进行扫描
./ary --vulnscan --url xx.xx.xx.xx --engine xray -v

# 对目标进行被动扫描（rad+xray）
./ary --vulnscan --engine xray --url http://testphp.vulnweb.com/ -v --passive

# 对文件中的目标进行被动扫描
./ary --vulnscan --engine xray --input target.txt -v --passive

# 读取数据库中的数据进扫描
./ary --vulnscan --engine xray --keyword tomcat -v
./ary --vulnscan --engine xray --keyword tomcat -v --crawl
```

分开xray与爬虫进行漏洞扫描：

```bash
# 启动一个 xray 后台
./ary --vulnscan --engine xray --port 7778 --background -v

# 启动爬虫,将其流量代码到 xray 上
./ary --assertscan --engine crawlergo --url http://testphp.vulnweb.com/ -v --passive --port 7778
./ary --assertscan --engine rad --url http://testphp.vulnweb.com/ -v --passive --port 7778
./ary --assertscan --engine gospider --url http://testphp.vulnweb.com/ -v --passive --port 7778
```

### PoC 漏洞验证

```bash
./ary --pocscan --input redis.txt --poc redis -v

./ary --pocscan --url xx.xx.xx.xx --poc ./pocs/redis -v

./ary --pocscan --poc tomcat --keyword tomcat -v

./ary --pocscan --keyword redis --poc redis -v

./ary --pocscan --keyword redis --poc redis -v --limit 1 --dumppcap redis
./ary --pocscan --keyword thinkphp --poc thinkphp_rce2 -v --limit 20 --dumppcap thinkphp

# 写到数据库
./ary --pocscan --url xx.xx.xx.xx --poc redis -v --limit 2 --upload
```


### 执行流

1. 获取 redis 所有网站并对其进行poc漏洞扫描

```bash
# 收集网站
./ary --netsearch --engine shodan --keyword reids -v --limit 100
# 打 poc
./ary --pocscan --keyword redis --poc redis -v
```

```bash
# 收集网站
./ary --netsearch --engine shodan --keyword harbor -v --limit 100
./ary --netsearch --engine censys --keyword harbor -v --limit 1000
# 打 poc
./ary --pocscan --keyword harbor --poc harbor -v
# 发现有检出的，使用 url 进行检测
./ary --pocscan --url "xxx.com" --poc harbor -v --dumppcap cve-2019-16097
```

2. 对一个网站进行渗透

```bash
./ary --vulnscan --engine xray --url http://testphp.vulnweb.com/ -v --passive
```

3. 获取到 redis 网站并对所有 redis ip 进行渗透

```bash
./ary --netsearch --engine shodan --keyword reids -v --limit 100
./ary --vulnscan --engine xray --keyword redis -v --limit 100
```

使用 stream 模块来实现执行流

这样子就可以把上面所有的多步骤内容变成一条命令，从而一键执行。

```bash
./ary -v --stream --keyword "redis 未授权访问漏洞"
# 默认使用 streams.yaml 文件，也可以指定别的执行流文件
./ary -v --stream --input streams.yaml --keyword "redis 未授权访问漏洞"
```

### 录包

只要在最后加入 --dumppcap 即可。

```bash
./ary --pocscan --keyword thinkphp --poc thinkphp_rce2 -v --limit 20 --dumppcap thinkphp
```

### suricata 测试

可以对 suricata 规则进行测试, 需先拉取和启用 suricata 容器 (注意：本功能需要社区版权限)

```bash
./ary --docker --action run --engine suricata --pcap thinkphp --rule thinkphp -v
```

### 导入认证证书

只要将 *.crt 放在 config 目录下，就可以使用了。

```bash
# 验证此社区版本证书可用，返回有效性和有效时间，需要放在目录下才可用
./ary --auth --input community.crt -v
```

### 杀死进程

如启动部分后台进程功能时，有僵尸进程时使用

```bash
# 主进程
./ary --kill -v
# 引擎进程
./ary --kill --engine xray -v
# 引擎进程，带端口
./ary.py --kill --engine xray --port 7778 -v 
```

## 场景示例

### 场景1：攻击到防御的规则编写指南

使用这个工具，可以解决我们目前安全能力的需求，一方面是红队的规则，主要是漏洞的 PoC，现在同时支持了 pocsutie3 和 xray yaml 的规则格式，另一方面是蓝队的规则，主要是 suricata 的检测规则，可以支持编写与测试。目前已经能够使用  Ary 进行攻击规则、流量检测规则的流程走通。

1、下载 ary ，需环境： centos

https://github.com/TeraSecTeam/ary/releases/

需要使用证书才能进行 suricata 规则编写与测试功能，私聊我获取。

2、装 suricata 的 docker环境

```bash
# 装环境
yum install docker -y
service docker start
# 启动 suricata docker
./ary --docker --action start --engine suricata -v
```

3、编写攻击规则 - 漏洞 PoC

可以使用 pocsuite3 和 xray yaml 两种格式进行编写

pocsuite3格式：

参考：http://pocsuite.org/

xray yaml 格式：

参考：https://docs.xray.cool/#/guide/poc

4、编写防守规则 - 编写 suricata 测试规则

```yaml
gid: 200863  # 组编号
component: thinkphp  # 组件名
phase: 2  # 阶段
severity: 1  # 风险等级
confidence: 2  # 规则可信度
category: 攻击利用  # 风险类型
sec_class: 漏洞利用  # 安全分类
description: ThinkPHP是一套开源的、基于PHP的轻量级Web应用开发框架。  #  描述
solution: 建议升级至最新版本  #  解决方案
keywords: thinkphp
vulnerability_01:  # 漏洞
    point_01:  # 探测点
      rule_name: Thinkphp 5.0.x 远程命令执行尝试
      rule: 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"riskIVY-PRS INFO Thinkphp 5.0.x RCE Exploitation Attempt"; flow:established,to_server; content:"GET"; http_method; content:"/index.php?s="; http_uri; content:"\\app/invokefunction&function=call_user_func_array"; http_uri; distance:0; pcre:"/(phpinfo|assert|system|eval)/i";classtype:web-application-attack; sid:94640317; rev:1; metadata:created_at 2020_05_14, updated_at 2020_05_14;)'
      state: 1  # 规则开关，1表示启用
      remote: 1  # 是否为远程利用
      local: 1  # 是否为本地利用
      phase: 2  # 攻击阶段
      severity: 1  # 风险等级
      confidence: 2  # 置信度
      category: 攻击利用  # 风险类型
      sec_class: 漏洞利用  # 安全分类
      description: ThinkPHP是一套开源的、基于PHP的轻量级Web应用开发框架。  #  风险描述
      solution: 建议升级至最新版本  #  解决方案
    point_02:
      state: 1
      rule: 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg : "riskIVY-PRS INFO Thinkphp 2.x RCE Exploitation Attempt";content:"$%7B@";pcre:"/(phpinfo|assert|system|eval)/i";classtype:web-application-attack; sid:94640315; rev:1; metadata:created_at 2020_05_14, updated_at 2020_05_14;)'
    point_03:
      state: 1
      rule: 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg : "riskIVY-PRS INFO Thinkphp5.0.23 RCE Exploitation Attempt";content:"POST /";content:"?s=captcha";pcre:"/_method=__construct&filter\[\]=system&method=get&server\[REQUEST_METHOD\]=/i";classtype:web-application-attack; sid:94640316; rev:1; metadata:created_at 2020_05_14, updated_at 2020_05_14;)'
```

5、整个流程的攻击到规则的测试流程

通过执行流实现自动打流量到检出规则的测试，红队与蓝队的结合。

```yaml
checkrule:
  name: checkrule
  steps:
  - pocscan: True  # 第一步，拉取 pocsuite poc
    update: True
    keyword: poc
    v: True
  - netsearch: True  # 第二步，收集 thinkphp 域名
    engine: fofa
    keyword: thinkphp
    limit: 10
    v: True
  - pocscan: True  # 第三步，使用 thinkphp 相关 poc 打流量并录成流量包
    keyword: thinkphp
    poc: Think_RCE_invokefunction_1
    limit: 10
    dumppcap: thinkphp
    v: True
  - command: mv output/thinkphp*.pcap mounts/pcaps/  # 第四步，将流量包移动到挂载目录下
  - docker: True  # 第五步，进行测试
    action: run
    engine: suricata
    pcap: thinkphp
    rule: thinkphp
    v: True
```

执行上面的执行流示例：

```bash
./ary --stream --keyword checkrule -v
```

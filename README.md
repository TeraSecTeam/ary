# Ary

![x](./doc/ARY.png)

Ary 是一个集成类工具，主要用于调用各种安全工具，从而形成便捷的一键式渗透。

> 版本：2.0.0  公开版
>
> 作者： Ali0th
>
> 联系： martin2877@foxmail.com
>
> 主页： github.com/Martin2877
>
> 声明：本工具仅供学习、测试使用，严禁用于非法用途，开发者对使用者的违法行为不负责任。

## 功能

0. 信息收集工具(开发中)
1. 通过多个网络空间的搜索引擎批量爬取相应网站, 如 Fofa, shodan, censys
2. 通过资产识别工具探测，如 ARL, Rad, crawlgo, gospider
3. 非指向性漏扫工具， 如 xray, (AWVS, MSF 开发中)
4. 通过 PoC 工具验证漏洞，如 pocsuite, (osprey 开发中)
5. webshell 管理工具批量 getshell, 如 CobaltStrike, antsword (此模块开发中)
6. 录包工具
7. 执行流

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

## 安装

1.安装所有的工具引擎：

```bash
./ary --vulnscan --engine all --update -v
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

## 使用

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

```bash
./ary -v --stream --input streams.yaml --keyword "redis 未授权访问漏洞"
```


### 录包

只要在最后加入 --dumppcap 即可。

```bash
./ary --pocscan --keyword thinkphp --poc thinkphp_rce2 -v --limit 20 --dumppcap thinkphp
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

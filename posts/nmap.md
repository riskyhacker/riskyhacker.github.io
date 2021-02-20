---
title: Nmap 
description: A quickstart guide for Nmap 
date: 2021-02-19
tags:
  - Hacking 
  - CTFT 
layout: layouts/post.njk
---

> A quick start guide.

### Documentation 
Nmap has awesome website packed with great information. [Port scanning](https://nmap.org/book/port-scanning-options.html) is a good enough synopsis to get you started. Checkout [the free online book](https://nmap.org/book/toc.html) when you need an all exhaustive reference. The purchased edition has extra goodies in it. The man page is just as awesome as the website.
``` text/0,8
# Loaded with useful content (unlike some man pages)
➜  ~ man nmap
NMAP(1)                                Nmap Reference Guide                                NMAP(1)

NAME
       nmap - Network exploration tool and security / port scanner

SYNOPSIS
       nmap [Scan Type...] [Options] {target specification}
```

### Default Scan / Half Open
If you don't supply any arguments, the default flags are `-sS`. If you ever need to search for what a flag means (for most linux CLI tools), don't fret, you're not limited to the man pages. Try [`explain shell`](https://explainshell.com). I'll leave the explainations to explain shell and just show you common commands.

#### [`nmap -sS {target specification}`](https://explainshell.com/explain?cmd=nmap+-sS)
``` text/0,6-21
➜  ~ nmap target.hacker
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 03:31 UTC
Nmap scan report for target.hacker (172.19.0.2)
Host is up (0.000011s latency).
Not shown: 984 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
6667/tcp open  irc
MAC Address: 02:42:AC:13:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
```

### Version Scan

You may notice this scan type takes longer than the half-open scan. The wait is justifiable because we need version numbers so we can scope potential vulnerabilities. If you ever need a scan status update while you're waiting, try pressing the spacebar.  

#### [`nmap -sV {target specification}`](https://explainshell.com/explain?cmd=nmap+-sV)

```text/0,3-5,11-26
➜  ~ nmap -sV target.hacker
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 03:49 UTC

# spacebar
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 03:49 (0:00:06 remaining)

Nmap scan report for target.hacker (172.19.0.2)
Host is up (0.000011s latency).
Not shown: 984 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec?
513/tcp  open  login
514/tcp  open  tcpwrapped
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  ingreslock?
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
6667/tcp open  irc         UnrealIRCd
# ... omit ...
Nmap done: 1 IP address (1 host up) scanned in 152.74 seconds
```

### Verbosity, Timing, and Pruning
You may want to try and speed up your scans. And likely you want to view the progress of ongoing scans. That's where verbosity and timing come in. Just like timing, there are multiple levels of verbosity. Triple verbosity (`-vvv`) lets you view ports as they are discovered. If no timing is specified (`-T`) then a default timing of `-T3` is assumed. Recommended typical use is `-T4`. Finally, you can prune the number of ports scanned (top 1000 by default) with `--top-ports` to scan specific ports.

#### [`nmap -vvv -sV -T4 --top-ports 20 {target specification}`](https://explainshell.com/explain?cmd=nmap++-vvv+-sV+-T4)

``` text/0,11-20,35-54
➜  ~ nmap -vvv -sV -T4 --top-ports 20 target.hacker
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 04:16 UTC
NSE: Loaded 45 scripts for scanning.
Initiating ARP Ping Scan at 04:16
Scanning target.hacker (172.19.0.2) [1 port]
Completed ARP Ping Scan at 04:16, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:16
Completed Parallel DNS resolution of 1 host. at 04:16, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 04:16
Scanning target.hacker (172.19.0.2) [20 ports]
Discovered open port 3306/tcp on 172.19.0.2
Discovered open port 25/tcp on 172.19.0.2
Discovered open port 22/tcp on 172.19.0.2
Discovered open port 139/tcp on 172.19.0.2
Discovered open port 23/tcp on 172.19.0.2
Discovered open port 445/tcp on 172.19.0.2
Discovered open port 111/tcp on 172.19.0.2
Discovered open port 21/tcp on 172.19.0.2
Completed SYN Stealth Scan at 04:16, 0.02s elapsed (20 total ports)
Initiating Service scan at 04:16
Scanning 8 services on target.hacker (172.19.0.2)
Completed Service scan at 04:16, 11.02s elapsed (8 services on 1 host)
NSE: Script scanning 172.19.0.2.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 04:16
Completed NSE at 04:16, 0.02s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 04:16
Completed NSE at 04:16, 0.00s elapsed
Nmap scan report for target.hacker (172.19.0.2)
Host is up, received arp-response (0.000014s latency).
Scanned at 2021-02-20 04:16:01 UTC for 11s

PORT     STATE  SERVICE       REASON         VERSION
21/tcp   open   ftp           syn-ack ttl 64 vsftpd 2.3.4
22/tcp   open   ssh           syn-ack ttl 64 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open   telnet        syn-ack ttl 64 Linux telnetd
25/tcp   open   smtp          syn-ack ttl 64 Postfix smtpd
53/tcp   closed domain        reset ttl 64
80/tcp   closed http          reset ttl 64
110/tcp  closed pop3          reset ttl 64
111/tcp  open   rpcbind       syn-ack ttl 64 2 (RPC #100000)
135/tcp  closed msrpc         reset ttl 64
139/tcp  open   netbios-ssn   syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  closed imap          reset ttl 64
443/tcp  closed https         reset ttl 64
445/tcp  open   netbios-ssn   syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
993/tcp  closed imaps         reset ttl 64
995/tcp  closed pop3s         reset ttl 64
1723/tcp closed pptp          reset ttl 64
3306/tcp open   mysql         syn-ack ttl 64 MySQL 5.0.51a-3ubuntu5
3389/tcp closed ms-wbt-server reset ttl 64
5900/tcp closed vnc           reset ttl 64
8080/tcp closed http-proxy    reset ttl 64
MAC Address: 02:42:AC:13:00:02 (Unknown)
Service Info: Host:  metasploitable.localdomain; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.41 seconds
           Raw packets sent: 21 (908B) | Rcvd: 21 (860B)
```

### Nmap Scripting Engine (NSE)
There are lots of NSE scripts available on a fresh install of Nmap, but you also want to make sure the script database is updated.

#### [`nmap --script-updatedb`](https://explainshell.com/explain?cmd=nmap+--script-updatedb)
```text/0,3,6
➜  ~ nmap --script-updatedb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 04:31 UTC
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.29 seconds
➜  ~ 
➜  ~ find /usr/share/nmap/scripts -type f -name '*ssl*'
/usr/share/nmap/scripts/ssl-dh-params.nse
/usr/share/nmap/scripts/ssl-cert-intaddr.nse
/usr/share/nmap/scripts/ssl-cert.nse
/usr/share/nmap/scripts/ssl-heartbleed.nse
/usr/share/nmap/scripts/ssl-poodle.nse
/usr/share/nmap/scripts/ssl-date.nse
/usr/share/nmap/scripts/ssl-known-key.nse
/usr/share/nmap/scripts/ssl-enum-ciphers.nse
/usr/share/nmap/scripts/rmi-vuln-classloader.nse
/usr/share/nmap/scripts/sslv2-drown.nse
/usr/share/nmap/scripts/ssl-ccs-injection.nse
/usr/share/nmap/scripts/sslv2.nse
```

Now that we have a handy script, lets save the output. There are three versions of output. If you'd like all three (better to have and not need) then use the flag `-oA` followed by the output filename (no file extension).

#### [`nmap --script={scriptname}`](https://explainshell.com/explain?cmd=nmap+--script%3D)
```text/0,3,6
➜  ~ nmap -sV -T4 --top-ports 20 --script=vulners -oA vulners_top_ports_20 target.hacker
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 04:47 UTC
Nmap scan report for target.hacker (172.19.0.2)
# ... omit ...
➜  ~ ls
vulners_top_ports_20.gnmap  vulners_top_ports_20.nmap  vulners_top_ports_20.xml
```

The output is a little noisy. Results like this are often times better views as a report. The linux utility `xsltproc` can convert the `.xml` output to an `.html` report. 

#### [`xsltproc -o {output}.html {input}.xml`](https://explainshell.com/explain?cmd=xsltproc+-o)

```shell/
➜  ~ xsltproc -o vulners_top_ports_20.html vulners_top_ports_20.xml
```
<style>
.center {
  display: block;
  margin-left: auto;
  margin-right: auto;
  width: 100%;
  border: 0.1rem solid black;
}
</style>
<img  class="center" src="{{ '/img/xsltproc.png' }}"/>

### Leveling up Nmap

We obviously didn't cover Nmap exhaustively (saved as an exercise for the reader), nor did we touch on actually understanding the results, which is arguably the most important part. Nonetheless,there are a couple ways to more efficiently leverage Nmap, each with their own tradeoff. You may find you gain functionality in some areas, while losing functionality in others.     
- [AutoRecon](https://github.com/Tib3rius/AutoRecon)
- [NmapAutomator](https://github.com/21y4d/nmapAutomator)
- [Rustscan](https://github.com/RustScan/RustScan)
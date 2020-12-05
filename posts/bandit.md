---
title: Bandit
description: Over The Wire walkthrough series 
date: 2020-08-29
tags:
  - Hacking 
  - Wargames
layout: layouts/post.njk
---

> An Over The Wire wargame.

### Getting into OTW
``` shell/1/
# SSH into OTW on port `2220`
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

### Level 0
``` shell/3/
# Objective: print file to standard out 
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
bandit0@bandit:~$
```

### Level 1
``` shell/3/
# Objective: print reserved-name file to standard out
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
bandit1@bandit:~$
```

### Level 2
``` shell/3/
# Objective: print filename with spaces to standard out 
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat spaces\ in\ this\ filename
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

### Level 3
``` shell/6/
# Objective: list hidden files
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ ls inhere/
bandit3@bandit:~$ ls -a inhere/
.  ..  .hidden
bandit3@bandit:~$ cat inhere/.hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
bandit3@bandit:~$
```

### Level 4
``` shell/5/
# Objective: Find only human-readable files
bandit4@bandit:~$ ls
inhere
bandit4@bandit:~$ ls inhere/
-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09
bandit4@bandit:~$ cat $(find inhere/ -type f | xargs -n 1 file | grep ASCII | cut -d ':' -f1)
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
bandit4@bandit:~$
```

### Level 5
``` shell/6,20/
# Objective: Find the only human-readable files 1033 bytes in size and not executable
bandit5@bandit:~$ ls
inhere
bandit5@bandit:~$ ls inhere/
maybehere00  maybehere02  maybehere04  maybehere06  maybehere08  maybehere10  maybehere12  maybehere14  maybehere16  maybehere18
maybehere01  maybehere03  maybehere05  maybehere07  maybehere09  maybehere11  maybehere13  maybehere15  maybehere17  maybehere19
bandit5@bandit:~$ ls inhere/*
inhere/maybehere00:
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3

inhere/maybehere01:
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3

...

inhere/maybehere18:
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3

inhere/maybehere19:
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3
bandit5@bandit:~$ cat $(find inhere -type f ! -executable -size 1033c | xargs -n 1 file | grep 'ASCII' | cut -d ':' -f1)
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

### Level 6
``` shell/23-24/
# Objective: Find the only file owned by user bandit7 owned by group bandit6 that is 33 bytes in size
# Key insight: ignore files you do not have permission to access
bandit6@bandit:~$ ls
bandit6@bandit:~$ ls -la
total 20
drwxr-xr-x  2 root root 4096 May  7 20:14 .
drwxr-xr-x 41 root root 4096 May  7 20:14 ..
-rw-r--r--  1 root root  220 May 15  2017 .bash_logout
-rw-r--r--  1 root root 3526 May 15  2017 .bashrc
-rw-r--r--  1 root root  675 May 15  2017 .profile
bandit6@bandit:~$ ls ..
bandit0   bandit12  bandit16  bandit2   bandit23  bandit27      bandit29      bandit30-git  bandit33  bandit7
bandit1   bandit13  bandit17  bandit20  bandit24  bandit27-git  bandit29-git  bandit31      bandit4   bandit8
bandit10  bandit14  bandit18  bandit21  bandit25  bandit28      bandit3       bandit31-git  bandit5   bandit9
bandit11  bandit15  bandit19  bandit22  bandit26  bandit28-git  bandit30      bandit32      bandit6
bandit6@bandit:~$ ls ../..
bin   cgroup2  etc   initrd.img      lib    lib64   lost+found  mnt  proc        root  sbin   srv  tmp  var      vmlinuz.old
boot  dev      home  initrd.img.old  lib32  libx32  media       opt  README.txt  run   share  sys  usr  vmlinuz
bandit6@bandit:~$ ls ../../../
bin   cgroup2  etc   initrd.img      lib    lib64   lost+found  mnt  proc        root  sbin   srv  tmp  var      vmlinuz.old
boot  dev      home  initrd.img.old  lib32  libx32  media       opt  README.txt  run   share  sys  usr  vmlinuz
bandit6@bandit:~$ find ../../ -type f -group bandit6 -user bandit7 -size 33c 2>/dev/null
../../var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat $(!!)
cat $(find ../../ -type f -group bandit6 -user bandit7 -size 33c 2>/dev/null)
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
bandit6@bandit:~$

```

### Level 7
``` shell/9/
# Objective: parse a file for desired keyword
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ du -h data.txt
4.0M    data.txt
bandit7@bandit:~$ wc data.txt
  98567  197133 4184396 data.txt
bandit7@bandit:~$ grep "millionth" data.txt
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
bandit7@bandit:~$ echo $(grep "millionth" data.txt ) | cut -d ' ' -f2
cvX2JJa4CFALtqS87jk27qwqGhBM9plV
bandit7@bandit:~$
```

### Level 8
``` shell/7/
# Objective: parse a file for unique occurences
bandit8@bandit:~$ ls
data.txt
bandit8@bandit:~$ du -h data.txt
36K     data.txt
bandit8@bandit:~$ wc data.txt
1001  1001 33033 data.txt
bandit8@bandit:~$ sort data.txt | uniq -c | grep -E '\ 1\ ' | awk '{print $2}'
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
bandit8@bandit:~$
```

### Level 9
``` shell/10,17/
# Objective: parse a file for human readable strings
bandit9@bandit:~$ ls
data.txt
bandit9@bandit:~$ ls data.txt
data.txt
bandit9@bandit:~$ file data.txt
data.txt: data
bandit9@bandit:~$ head -1024c data.txt
Llω;ßOܛǤXNdT$x7@D@o+DBM֢Z/,_w#5
...
bandit9@bandit:~$ strings data.txt | grep -E '[=]{2,}.*'
========== the*2i"4
========== password
Z)========== is
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
bandit9@bandit:~$ strings data.txt | grep -E '&[=]{2,}.*'
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
bandit9@bandit:~$ strings data.txt | grep -E '&[=]{2,}.*' | awk '{print $2}'
truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
bandit9@bandit:~$
```

### Level 10
``` shell/10/
# Objective: decode base64 data
bandit10@bandit:~$ ls
data.txt
bandit10@bandit:~$ file data.txt
data.txt: ASCII shell/
bandit10@bandit:~$ head data.txt
VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==
bandit10@bandit:~$ base64 --decode data.txt
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
bandit10@bandit:~$ echo $(!!) | awk '{ print $4}'
echo $(base64 --decode data.txt ) | awk '{ print $4}'
IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
bandit10@bandit:~$
```

### Level 11


``` shell/7/
# Objective: rotate plaintext 
bandit11@bandit:~$ ls
data.txt
bandit11@bandit:~$ head data.txt
Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m' | awk '{print $4}'
5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
bandit11@bandit:~$
```

### Level 12
``` shell/34/
# Objective: decode repeatedly compressed hexdump
bandit12@bandit:~$ ls
data.txt
bandit12@bandit:~$ file data.txt
data.txt: ASCII shell/
bandit12@bandit:~$ head data.txt
00000000: 1f8b 0808 0650 b45e 0203 6461 7461 322e  .....P.^..data2.
00000010: 6269 6e00 013d 02c2 fd42 5a68 3931 4159  bin..=...BZh91AY
00000020: 2653 598e 4f1c c800 001e 7fff fbf9 7fda  &SY.O...........
00000030: 9e7f 4f76 9fcf fe7d 3fff f67d abde 5e9f  ..Ov...}?..}..^.
00000040: f3fe 9fbf f6f1 feee bfdf a3ff b001 3b1b  ..............;.
00000050: 5481 a1a0 1ea0 1a34 d0d0 001a 68d3 4683  T......4....h.F.
00000060: 4680 0680 0034 1918 4c4d 190c 4000 0001  F....4..LM..@...
00000070: a000 c87a 81a3 464d a8d3 43c5 1068 0346  ...z..FM..C..h.F
00000080: 8343 40d0 3400 0340 66a6 8068 0cd4 f500  .C@.4..@f..h....
00000090: 69ea 6800 0f50 68f2 4d00 680d 06ca 0190  i.h..Ph.M.h.....
bandit12@bandit:~$ xxd -r data.txt | file -
/dev/stdin: gzip compressed data, was "data2.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:~$ xxd -r data.txt | gunzip | file -
/dev/stdin: bzip2 compressed data, block size = 900k
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | file -
/dev/stdin: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | file -
/dev/stdin: POSIX tar archive (GNU)
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | file -
/dev/stdin: POSIX tar archive (GNU)
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | tar -xO | file -
/dev/stdin: bzip2 compressed data, block size = 900k
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | tar -xO | bunzip2 | file -
/dev/stdin: POSIX tar archive (GNU)
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | tar -xO | bunzip2 | tar -xO | file -
/dev/stdin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | tar -xO | bunzip2 | tar -xO | gunzip | file -
/dev/stdin: ASCII shell/
bandit12@bandit:~$ xxd -r data.txt | gunzip | bunzip2 | gunzip | tar -xO | tar -xO | bunzip2 | tar -xO | gunzip | awk '{print $4}'
8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
bandit12@bandit:~$
```

### Level 13
``` shell/3/
# Objective: use a private ssh key to read a file
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
bandit14@bandit:~$ cat /etc/bandit\_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
bandit14@bandit:~$
```

### Level 14-15
``` shell/1,6/
# Objective: transmit data through a port on localhost
bandit14@bandit:~$ nc localhost 30000 <<< '4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e'
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr

bandit14@bandit:~$
bandit15@bandit:~$ openssl s_client -ign_eof -connect localhost:30001 <<< "BfMYroe26WYalil77FoDi9qh59eK5xNr"
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
Certificate chain
0 s:/CN=localhost
i:/CN=localhost
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEDU18oTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNTA3MTgxNTQzWhcNMjEwNTA3MTgxNTQzWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK3CPNFR
FEypcqUa8NslmIMWl9xq53Cwhs/fvYHAvauyfE3uDVyyX79Z34Tkot6YflAoufnS
+puh2Kgq7aDaF+xhE+FPcz1JE0C2bflGfEtx4l3qy79SRpLiZ7eio8NPasvduG5e
pkuHefwI4c7GS6Y7OTz/6IpxqXBzv3c+x93TAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAC9uy1rF2U/OSBXbQJYuPuzT5mYwcjEEV0XwyiX1MFZbKUlyFZUw
rq+P1HfFp+BSODtk6tHM9bTz+p2OJRXuELG0ly8+Nf/hO/mYS1i5Ekzv4PL9hO8q
PfmDXTHs23Tc7ctLqPRj4/4qxw6RF4SM+uxkAuHgT/NDW1LphxkJlKGn
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits

SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: A13E23D3F5EF2EAE12971CA9723AE9DA6DFA471036CA068A9BF2BEC40C7204B9
    Session-ID-ctx:
    Master-Key: BA6403AC3F4D7D538D391211AA0BA5FE0EE9349E42BDD5C8D64E7CBE12E5A8B42A3E54B456BADF8508AB57BFD39AD02B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa 02 e6 3a 2e 0b c8 5d-6f 54 4a 1b 5a e0 2c 0e   ...:...]oTJ.Z.,.
    0010 - 19 75 44 d7 13 60 84 9f-93 a0 48 e0 07 ed 93 e0   .uD..`....H.....
    0020 - de 67 fe 08 43 4d 2f 01-f5 8c 29 87 58 72 bf e6   .g..CM/...).Xr..
    0030 - ea 74 61 29 d2 fc 7b 74-4f 06 13 5c be 4f 0f a8   .ta)..{tO..\.O..
    0040 - 0f c8 47 ae 3f 0d 64 15-c5 2d 21 30 8b 25 80 ab   ..G.?.d..-!0.%..
    0050 - 87 0b 3b 67 44 ba 9d 0a-08 5a 88 7d e0 1f 29 5f   ..;gD....Z.}..)_
    0060 - 74 c2 b3 7f e9 97 21 62-86 d8 98 36 11 cd fa 52   t.....!b...6...R
    0070 - 11 d6 c8 0d 3b a8 a0 f0-78 10 0e 45 af a0 e6 f9   ....;...x..E....
    0080 - 10 23 0e 1b 79 f2 16 f4-2a 80 28 45 c9 1b 2b 98   .#..y...*.(E..+.
    0090 - 00 8d 01 cf b9 59 01 03-6a d5 54 b5 b8 53 8e 5e   .....Y..j.T..S.^
Start Time: 1598750519
Timeout   : 7200 (sec)
Verify return code: 18 (self signed certificate)
Extended master secret: yes
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
closed
bandit15@bandit:~$
```
### Level 16

``` shell/1,21-25,29,59-63,65,166-194,197/136-162,196
# Objective: Discover open ports and protocol versions, send encrypted message to open port
bandit16@bandit:~$ nmap -vvv -T5 -p 31000-32000 localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2020-08-30 03:39 CEST
Initiating Ping Scan at 03:39
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 03:39, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 03:39
Scanning localhost (127.0.0.1) [1001 ports]
Discovered open port 31518/tcp on 127.0.0.1
Discovered open port 31960/tcp on 127.0.0.1
Discovered open port 31691/tcp on 127.0.0.1
Discovered open port 31046/tcp on 127.0.0.1
Discovered open port 31790/tcp on 127.0.0.1
Completed Connect Scan at 03:39, 0.04s elapsed (1001 total ports)
Nmap scan report for localhost (127.0.0.1)
Host is up, received conn-refused (0.00024s latency).
Scanned at 2020-08-30 03:39:31 CEST for 0s
Not shown: 996 closed ports
Reason: 996 conn-refused
PORT      STATE SERVICE REASON
31046/tcp open  unknown syn-ack
31518/tcp open  unknown syn-ack
31691/tcp open  unknown syn-ack
31790/tcp open  unknown syn-ack
31960/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
bandit16@bandit:~$ nmap -vvv -T5 -sV -p 31046,31518,31691,31790,31960 localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2020-08-30 03:40 CEST
NSE: Loaded 40 scripts for scanning.
Initiating Ping Scan at 03:40
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 03:40, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 03:40
Scanning localhost (127.0.0.1) [5 ports]
Discovered open port 31046/tcp on 127.0.0.1
Discovered open port 31518/tcp on 127.0.0.1
Discovered open port 31960/tcp on 127.0.0.1
Discovered open port 31691/tcp on 127.0.0.1
Discovered open port 31790/tcp on 127.0.0.1
Completed Connect Scan at 03:40, 0.00s elapsed (5 total ports)
Initiating Service scan at 03:40
Scanning 5 services on localhost (127.0.0.1)
Service scan Timing: About 20.00% done; ETC: 03:43 (0:02:44 remaining)
ompleted Service scan at 03:41, 89.43s elapsed (5 services on 1 host)
NSE: Script scanning 127.0.0.1.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 03:41
Completed NSE at 03:41, 0.02s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 03:41
Completed NSE at 03:41, 0.01s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up, received conn-refused (0.00055s latency).
Scanned at 2020-08-30 03:40:26 CEST for 89s
PORT      STATE SERVICE     REASON  VERSION
31046/tcp open  echo        syn-ack
31518/tcp open  ssl/echo    syn-ack
31691/tcp open  echo        syn-ack
31790/tcp open  ssl/unknown syn-ack
31960/tcp open  echo        syn-ack
bandit16@bandit:~$
bandit16@bandit:~$ openssl s_client -ign_eof -connect localhost:31790 <<< cluFn7wTiGryunymYOu4RcffSxQluehd
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
Certificate chain
0 s:/CN=localhost
i:/CN=localhost
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEOxBGEjANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNzExMTM1NjI4WhcNMjEwNzExMTM1NjI4WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALjlJy1H
hxygfKR5X5QT8dbHVAqKBGZPWUutQJE5E7Ic+xKGl1BAVFzJmbGnJ8cxHgpSubDW
urtfkIPgu/vyyIhYn4jhmgkJOWuHc7mxRl64TVYfxMh6YpalOQ1aQeNsOtYgUoqA
+aG3Sa4eCaBNawS+CgV6EEnx0LICSN7cTRATAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAKHnag1vqMuJu3G3CTM/6pJWW14JvOoDwtTas8EgG6rLrBxNV8uU
HutrzqeW9EANLBnQyDytynWzU9fNh1TWtEVku1X/TLizuQb5EGF6pRE1n6LF9ptJ
CQkvW1CH8eOILuQcbPyjg+/43FM3ByVXtQmTEhORm7olAo8upbFLdTd0
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---

No client certificate CA names sent
Peer signing digest: SHA512

Server Temp Key: X25519, 253 bits
---

SSL handshake has read 1019 bytes and written 269 bytes

Verification error: self signed certificate
---

New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 5A593A7B626DC9D3AD7B828DDD37B36211FC544EF61030E07A7EB75DB9B76D0F
    Session-ID-ctx:
    Master-Key: 37DFFC6D6B5F3BE16333C74F33C83E47611833E55B0E34128D5521A8A40879708F71C3EE44F1CE1CD514D7C9826D1BE1
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 71 24 75 25 65 da ee 1d-04 f1 98 ed 3f 34 fb af   q$u%e.......?4..
    0010 - f3 c4 c2 a1 07 59 c3 74-54 07 15 e7 40 fe ef 46   .....Y.tT...@..F
    0020 - 5d f8 e1 50 8f 72 dc 86-fb e2 03 fe 77 d5 49 83   ]..P.r......w.I.
    0030 - 29 11 93 00 5c cf aa d5-f4 25 ca 0a 27 e8 56 1e   )...\....%..'.V.
    0040 - f1 fa b5 18 43 2a 49 1b-98 31 a2 4e 5c a1 c8 87   ....C*I..1.N\...
    0050 - 90 a6 ab a6 1f 54 8e 6c-99 1c 60 c6 4d 18 8c 51   .....T.l..`.M..Q
    0060 - b0 03 3c 2a 68 7f d1 47-da ae 33 6b 18 90 9b 52   ..<*h..G..3k...R
    0070 - 33 33 3f 90 e4 d0 6f 52-63 b0 2b ed 92 ea 73 57   33?...oRc.+...sW
    0080 - ea b0 06 39 2c af 9d 0d-75 36 2f e3 c6 f9 f4 b1   ...9,...u6/.....
    0090 - 48 9e f1 d4 48 d3 cc e0-c4 d8 5a 3a d2 f8 80 47   H...H.....Z:...G
Start Time: 1598752160
Timeout   : 7200 (sec)
Verify return code: 18 (self signed certificate)
Extended master secret: yes
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
bandit16@bandit:~$
bandit16@bandit:~$ << EOF > id_rsa.key
heredoc> -----BEGIN RSA PRIVATE KEY-----
heredoc> MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
heredoc> imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
heredoc> Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
heredoc> DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
heredoc> JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
heredoc> x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
heredoc> KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
heredoc> J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
heredoc> d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
heredoc> YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
heredoc> vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
heredoc> +TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
heredoc> 8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
heredoc> SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
heredoc> HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
heredoc> SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
heredoc> R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
heredoc> Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
heredoc> R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
heredoc> L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
heredoc> blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
heredoc> YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
heredoc> 77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
heredoc> dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
heredoc> vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
heredoc> -----END RSA PRIVATE KEY-----
heredoc> EOF
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
bandit16@bandit:~$ chmod 600 id_rsa.key
bandit16@bandit:~$ ssh -i id_rsa.key bandit17@bandit.labs.overthewire.org -p 2220
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn
```
### Level 17

``` shell/14/
# Objective: Determine differences between files
bandit17@bandit:~$ ls
passwords.new  passwords.old
bandit17@bandit:~$ ls -la
total 36
drwxr-xr-x  3 root     root     4096 Jul 11 15:56 .
drwxr-xr-x 41 root     root     4096 May  7 20:14 ..
-rw-r-----  1 bandit17 bandit17   33 Jul 11 15:56 .bandit16.password
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r-----  1 bandit18 bandit17 3300 May  7 20:14 passwords.new
-rw-r-----  1 bandit18 bandit17 3300 May  7 20:14 passwords.old
-rw-r--r--  1 root     root      675 May 15  2017 .profile
drwxr-xr-x  2 root     root     4096 Jul 11 15:56 .ssh
bandit17@bandit:~$ diff passwords.new passwords.old
42c42

< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
```
### Level 18

``` shell/6/
# Objective: Bypass ssh logout from .bashrc configuration
bandit17@bandit:~$ ssh bandit18@localhost
Enjoy your stay!
Byebye !
Connection to localhost closed.
bandit17@bandit:~$
bandit17@bandit:~$ ssh -t bandit18@localhost /bin/sh
$ 
$ whoami
bandit18
$ ls
readme
$ cat readme
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

### Level 19

``` shell/11/
# Objective: use setUID bit binary
bandit19@bandit:~$ ls
bandit20-do
bandit19@bandit:~$ ls -la bandit20-do
-rwsr-x--- 1 bandit20 bandit19 7296 May  7 20:14 bandit20-do
bandit19@bandit:~$ file bandit20-do
bandit20-do: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8e941f24b8c5cd0af67b22b724c57e1ab92a92a1, not stripped
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$
bandit19@bandit:~$ ./bandit20-do /bin/cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```


### Level 20
``` shell/9,13/
# Objective: Create a socket listener as a background job 
bandit20@bandit:~$ ls
suconnect
bandit20@bandit:~$ ls -la suconnect
-rwsr-x--- 1 bandit21 bandit20 12088 May  7 20:14 suconnect
bandit20@bandit:~$ ./suconnect
Usage: ./suconnect <portnumber>
This program will connect to the given port on localhost using TCP. If it receives the correct password from the other side, the next password is transmitted back.
bandit20@bandit:~$
bandit20@bandit:~$ echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -lvp 8888 &
[1] 4975
bandit20@bandit:~$ listening on [any] 8888 ...

bandit20@bandit:~$ ./suconnect 8888
connect to [127.0.0.1] from localhost [127.0.0.1] 36356
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
[1]+  Done                    echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -lvp 8888
bandit20@bandit:~$
```

### Level 21

``` shell/3,6/
# Objective: Inspect scheduled jobs/tasks
bandit21@bandit:~$ ls /etc/cron.d/
cronjob_bandit15_root  cronjob_bandit17_root  cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  cronjob_bandit25_root
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

### Level 22

``` shell/3,6,16,22/18-19
# Objective: Inspect scheduled jobs/tasks
bandit22@bandit:~$ ls /etc/cron.d/
cronjob_bandit15_root  cronjob_bandit17_root  cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  cronjob_bandit25_root
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

bandit22@bandit:~$ ls -la /usr/bin/cronjob_bandit23.sh
-rwxr-x--- 1 bandit23 bandit22 211 May  7 20:14 /usr/bin/cronjob_bandit23.sh
bandit22@bandit:~$ myname=bandit23
bandit22@bandit:~$ mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
bandit22@bandit:~$ echo $mytarget
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/$mytarget
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

#### Level 23
``` shell/5,8,29-30,36-37/38
# Objective: Inspect and manipulate scheduled jobs/tasks
# Key insight: permissions on interpretted scripts
bandit23@bandit:~$ ls /etc/cron.d/
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
bandit23@bandit:~$ cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

bandit23@bandit:~$
bandit23@bandit:~$ vi tmp/a130mb.sh  # create script
bandit23@bandit:~$ cat /tmp/a130mb.sh
    #!/bin/sh

    cp /etc/bandit_pass/bandit24 /tmp/a130mb.txt
    chmod 777 /tmp/a130mb.txt

bandit23@bandit:~$ chmod +x /tmp/a130mb.sh
bandit23@bandit:~$ cp /tmp/a130mb.sh /var/spool/bandit24/a130mb.sh
bandit23@bandit:~$ watch cat /tmp/a130mb.txt
bandit23@bandit:~$ cat /tmp/a130mb.txt
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

#### Level 24
``` shell/2-5,18/
# Objective: Brute force a service 
# Key insight: Generate a wordlist 
bandit24@bandit:~$ PASS=UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
bandit24@bandit:~$ for PIN in {0000..9999}; do
> echo $PASS $PIN
> done > /tmp/a130mb.txt
bandit24@bandit:~$
bandit24@bandit:~$ head /tmp/a130mb.txt
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0000
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0001
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0002
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0003
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0004
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0005
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0006
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0007
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0008
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0009
bandit24@bandit:~$ cat /tmp/a130mb.txt | nc localhost 30002
Wrong! Please enter the correct pincode. Try again.
Wrong! Please enter the correct pincode. Try again.
Wrong! Please enter the correct pincode. Try again.
Wrong! Please enter the correct pincode. Try again.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
bandit24@bandit:~$
``` 

### Level 25-26
``` shell/18-21,40 
# Objective: escape default login shell 
# Key insight: /etc/passwd; more has access to vi; vi has access to shell
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost
...
Connection to localhost closed
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showshell/
bandit25@bandit:~$ file /usr/bin/showshell/
/usr/bin/showshell/: POSIX shell script, ASCII shell/ executable
bandit25@bandit:~$ cat /usr/bin/showshell/
#!/bin/sh

export TERM=linux

more ~/shell/.txt
exit 0
bandit25@bandit:~$ # resize screen; enter more's vim mode
v 
:set shell=/bin/bash
:shell
bandit26@bandit:~$ cat /etc/bandit_pass/bandit26
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
bandit26@bandit:~$
bandit26@bandit:~$ ls
bandit27-do  shell/.txt
bandit26@bandit:~$ cat shell/.txt
  _                     _ _ _   ___   __
| |                   | (_) | |__ \ / /
| |__   __ _ _ __   __| |_| |_   ) / /_
| '_ \ / _` | '_ \ / _` | | __| / / '_ \
| |_) | (_| | | | | (_| | | |_ / /| (_) |
|_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
bandit26@bandit:~$
bandit26@bandit:~$ ls -la bandit27-do
-rwsr-x--- 1 bandit27 bandit26 7296 May  7 20:14 bandit27-do
bandit26@bandit:~$ ./bandit27-do
Run a command as another user.
  Example: ./bandit27-do id
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```


#### Level 27
``` shell/1,18/
# Objective: clone a repository
bandit27@bandit:~$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo /tmp/a130mb
Cloning into '/tmp/a130mb'...
Could not create directory '/home/bandit27/.ssh'.
  The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

  bandit27-git@localhost's password:
remote: Counting objects: 3, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (3/3), done.
bandit27@bandit:~$ cd /tmp/a130mb
bandit27@bandit:/tmp/a130mb$ ls
README
bandit27@bandit:/tmp/a130mb$ cat README
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
bandit27@bandit:/tmp/a130mb$
```

#### Level 28
``` shell/20,33,46,55,58/30
# Objective: Find private information in a repository 
# Key insight: check the commit logs; checkout historic branch
bandit28@bandit:~$ git clone ssh://bandit28-git@localhost/home/bandit28-git/repo /tmp/a130mb
Cloning into '/tmp/a130mb'...
Could not create directory '/home/bandit28/.ssh'.
  The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit28/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

  bandit28-git@localhost's password:
remote: Counting objects: 9, done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (2/2), done.
bandit28@bandit:~$ cd /tmp/a130mb
bandit28@bandit:/tmp/a130mb$ ls
README.md
bandit28@bandit:/tmp/a130mb$ cat README.md
# Level Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx

bandit28@bandit:/tmp/a130mb$ git log --oneline
edd935d fix info leak
c086d11 add missing data
de2ebe2 initial commit of README.md
bandit28@bandit:/tmp/a130mb$ git checkout de2ebe2
Note: checking out 'de2ebe2'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at de2ebe2... initial commit of README.md
bandit28@bandit:/tmp/a130mb$ cat README.md
# Level Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: <TBD>

bandit28@bandit:/tmp/a130mb$ git checkout c086d11
Previous HEAD position was de2ebe2... initial commit of README.md
HEAD is now at c086d11... add missing data
bandit28@bandit:/tmp/a130mb$ cat README.md
# Level Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: bbc96594b4e001778eee9975372716b2
bbc96594b4e001778eee9975372716b2

bandit28@bandit:/tmp/a130mb$
```

#### Level 29
``` shell/36,41/
# Objective: Find private information in repository branches
bandit29@bandit:~$ git clone ssh://bandit29-git@localhost/home/bandit29-git/repo /tmp/a130mb
Cloning into '/tmp/a130mb'...
Could not create directory '/home/bandit29/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit29-git@localhost's password:
remote: Counting objects: 16, done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (16/16), 1.43 KiB | 0 bytes/s, done.
Resolving deltas: 100% (2/2), done.
bandit29@bandit:~$ cd /tmp/a130mb
bandit29@bandit:/tmp/a130mb$ ls
README.md
bandit29@bandit:/tmp/a130mb$ cat README.md
# Level Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>

bandit29@bandit:/tmp/a130mb$
bandit29@bandit:/tmp/a130mb$ git branch -a
  clear
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
bandit29@bandit:/tmp/a130mb$ git checkout dev
Branch dev set up to track remote branch dev from origin.
Switched to a new branch 'dev'
bandit29@bandit:/tmp/a130mb$ ls
code  README.md
bandit29@bandit:/tmp/a130mb$ cat README.md
# Level Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
5b90576bedb2cc04c86a9e924ce42faf

bandit29@bandit:/tmp/a130mb$
```

#### Level 30
``` shell/20,29,46,50/
# Objective: Find private information in a repository using tag branches 
bandit30@bandit:~$ git clone ssh://bandit30-git@localhost/home/bandit30-git/repo
fatal: could not create work tree dir 'repo': Permission denied
bandit30@bandit:~$ set -o vi
bandit30@bandit:~$ git clone ssh://bandit30-git@localhost/home/bandit30-git/repo /tmp/a130mb
Cloning into '/tmp/a130mb'...
Could not create directory '/home/bandit30/.ssh'.
  The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit30/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

  bandit30-git@localhost's password:
remote: Counting objects: 4, done.
remote: Total 4 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (4/4), done.
bandit30@bandit:~$ cd /tmp/a130mb
bandit30@bandit:/tmp/a130mb$ ls
README.md
bandit30@bandit:/tmp/a130mb$ cat README.md
just an epmty file... muahaha
bandit30@bandit:/tmp/a130mb$
bandit30@bandit:/tmp/a130mb$ ls -la
total 844
drwxr-sr-x    3 bandit30 root   4096 Aug 31 04:18 .
drwxrws-wt 3930 root     root 847872 Aug 31 04:22 ..
drwxr-sr-x    8 bandit30 root   4096 Aug 31 04:20 .git
-rw-r--r--    1 bandit30 root     30 Aug 31 04:18 README.md
bandit30@bandit:/tmp/a130mb$ cd .git/
bandit30@bandit:/tmp/a130mb/.git$ ls -la
total 52
drwxr-sr-x 8 bandit30 root 4096 Aug 31 04:20 .
drwxr-sr-x 3 bandit30 root 4096 Aug 31 04:18 ..
drwxr-sr-x 2 bandit30 root 4096 Aug 31 04:18 branches
-rw-r--r-- 1 bandit30 root  276 Aug 31 04:18 config
-rw-r--r-- 1 bandit30 root   73 Aug 31 04:18 description
-rw-r--r-- 1 bandit30 root    0 Aug 31 04:19 FETCH_HEAD
-rw-r--r-- 1 bandit30 root   23 Aug 31 04:20 HEAD
drwxr-sr-x 2 bandit30 root 4096 Aug 31 04:18 hooks
-rw-r--r-- 1 bandit30 root  137 Aug 31 04:20 index
drwxr-sr-x 2 bandit30 root 4096 Aug 31 04:18 info
drwxr-sr-x 3 bandit30 root 4096 Aug 31 04:18 logs
drwxr-sr-x 4 bandit30 root 4096 Aug 31 04:18 objects
-rw-r--r-- 1 bandit30 root  165 Aug 31 04:18 packed-refs
drwxr-sr-x 5 bandit30 root 4096 Aug 31 04:18 refs
bandit30@bandit:/tmp/a130mb/.git$ cat packed-refs
# pack-refs with: peeled fully-peeled
3aefa229469b7ba1cc08203e5d8fa299354c496b refs/remotes/origin/master
f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea refs/tags/secret
bandit30@bandit:/tmp/a130mb/.git$ git show secret
47e603bb428404d265f59c42920d81e5
bandit30@bandit:/tmp/a130mb/.git$
```

#### Level 31
``` shell/19,27-29,33/20-26
 Objective: Find private information in repository by trigger git hooks
bandit31@bandit:~$ git clone ssh://bandit31-git@localhost/home/bandit31-git/repo /tmp/a130mb
Cloning into '/tmp/a130mb'...
Could not create directory '/home/bandit31/.ssh'.
  The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

  bandit31-git@localhost's password:
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 4 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (4/4), 383 bytes | 0 bytes/s, done.
bandit31@bandit:~$ cd /tmp/a130mb
bandit31@bandit:/tmp/a130mb$
bandit31@bandit:/tmp/a130mb$ ls
README.md
bandit31@bandit:/tmp/a130mb$ cat README.md
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master

bandit31@bandit:/tmp/a130mb$ echo 'May I come in?' > key.txt
bandit31@bandit:/tmp/a130mb$ git add key.txt
bandit31@bandit:/tmp/a130mb$ git commit -m 'added key.txt'
[master 07c7910] added key.txt
1 file changed, 1 insertion(+)
create mode 100644 key.txt
bandit31@bandit:/tmp/a130mb$ git push
Could not create directory '/home/bandit31/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password:
Counting objects: 3, done.
Delta compression using up to 2 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 323 bytes | 0 bytes/s, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
To ssh://localhost/home/bandit31-git/repo
! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://bandit31-git@localhost/home/bandit31-git/repo'
56a9bf19c63d650ce78e6ec0354ee45e
```

#### Level 32
``` shell/5/
# Objective: Spawn a new shell
WELCOME TO THE UPPERCASE SHELL
>>
>> echo
sh: 1: ECHO: not found
>> $0
$ bash
bandit33@bandit:~$ ls
uppershell
bandit33@bandit:~$ ls -la uppershell
-rwsr-x--- 1 bandit33 bandit32 7556 May  7 20:14 uppershell
bandit33@bandit:~$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee
```

---
title: Hacking Reference 
description: Links to keep bookmarked while hacking.
date: 2020-11-11
tags:
  - Hacking 
layout: layouts/post.njk
---

> Useful links to keep bookmarked while hacking.

## Intelligence Gathering

During the Intelligence Gathering Phase, Hackers scan the Target Network. These scans gather information using various network and intelligence gathering utilities. 

### Reconnaissance

The objective of reconnaissance is to discover and confirm vulnerabilities while leveraging intelligence discovered during Intelligence Gathering. Reconnaissance activities also include identifying any rogue services or undiscovered vulnerabilities.

#### Passsive Reconnaissance

Passive reconnaissance is used to discover potential vulnerabilities without initiating an active connection.

**DNS/WEB**

* [CRT Certificate Search](https://crt.sh/)
* [Central Ops](https://centralops.net/co/)
* [DNS Enumeration Techniques](https://resources.infosecinstitute.com/topic/dns-enumeration-techniques-in-linux/#gref)
* [DNSRecon](https://github.com/darkoperator/dnsrecon)
* [DNSdumpster](https://dnsdumpster.com/)
* [GoBuster](https://github.com/OJ/gobuster)
* [Google Public DNS](https://dns.google.com/) `hot`
* [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
* [Robtex DNS Lookup](https://www.robtex.com/dns-lookup/)
* [ViewDNS Info](https://viewdns.info/)
* [W3DT](https://w3dt.net/)

**Email**

* [Have I Been Pwned](https://haveibeenpwned.com/)
* [LeakDB Threat Engine](https://joe.black/leakengine.html)
* [MxToolBox](https://mxtoolbox.com/)
* [SPF | Proofpoint](https://stopemailfraud.proofpoint.com/spf/)

#### OSINT

* [Exif and Metadata](http://metapicz.com/#landing)
* [FOCA](https://github.com/ElevenPaths/FOCA)
* [Goofile](https://tools.kali.org/information-gathering/goofile)
* [MetagooFil](https://tools.kali.org/information-gathering/metagoofil)
* [PastbinEnum](https://www.corelan.be/index.php/2011/03/22/pastenum-pastebinpastie-enumeration-tool/)
* [Recon-NG](https://securenetworkmanagement.com/recon-ng-tutorial-part-3/)
* [Wayback Machine](https://web.archive.org/web/20110929213744/http://nvd.nist.gov/scap/xccdf/docs/xccdf-spec-1.1.2-20060913.pdf)



#### Active Reconnaissance

Active reconnaissance is used to validate potential vulnerabilities discovered by passive reconnaissance. Additionally, it is used to uncover deficiencies not found during passive reconnaissance. 

* [Anonymous Port Scanning](https://www.shellhacks.com/Anonymous-Port-Scanning-Nmap-Tor-ProxyChains/)
* [AutoRecon](https://github.com/Tib3rius/AutoRecon)
* [Bookmarklets](https://www.squarefree.com/bookmarklets/)
* [FTP Bounce](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)
* [Fimap](https://github.com/kurobeats/fimap)
* [Fireprox](https://github.com/ustayready/fireprox)
* [Free Proxy List](https://free-proxy-list.net/)
* [Idle Scan](https://nmap.org/book/idlescan.html)
* [Pornzilla](https://www.squarefree.com/pornzilla/)
* [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
* [Ports Database](https://www.speedguide.net/ports.php)
* [Proxychains](https://null-byte.wonderhowto.com/how-to/hack-like-pro-evade-detection-using-proxychains-0154619/) 
* [TCP and UDP Port Numbers](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
* [TCPDump](https://danielmiessler.com/study/tcpdump/)
* [Tamper Monkey](https://www.tampermonkey.net/scripts.php)
* [Tshark](https://hackertarget.com/tshark-tutorial-and-filter-examples/)
* [WebSPHINX](https://www.cs.cmu.edu/~rcm/websphinx/)



## Vulnerability Analysis 

The objective of vulnerability analysis is to confirm the existence of vulnerabilities discovered during reconnaissance. Descriptions and in-depth information regarding the issues and remediation recommendations should be covered in other sections (Technical Summary).

* [BugCrowd University - Intro to Burp Suite](https://www.youtube.com/watch?v=h2duGBZLEek)
* [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/using)
* [Burp Suite for Penetration Testing](https://portswigger.net/burp/documentation/desktop/penetration-testing)
* [Chaining Proxies](https://cybersecuritylife.wordpress.com/2015/10/27/using-burp-suite-and-owasp-zap-at-the-same-time-chaining-proxys/)
* [CyberChef](https://gchq.github.io/CyberChef/)
* [Findsploit](https://github.com/1N3/Findsploit)
* [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)
* [Getsploit](https://vulners.com/products)
* [Intercept Proxies](https://owasp.org/www-pdf-archive/Intercept-proxies.pdf)
* [JSParser](https://github.com/nahamsec/JSParser)
* [MITM Proxy](https://hub.docker.com/r/mitmproxy/mitmproxy/)
* [NoSQL Wordlist](https://github.com/cr0hn/nosqlinjection_wordlists)
* [OpenVAS Docker](https://github.com/mikesplain/openvas-docker)
* [Port Swigger](https://portswigger.net/web-security)
* [PortSwigger Scanning Websites](https://portswigger.net/burp/documentation/desktop/scanning) 
* [Rapid7 Vulnerability & Exploit Database](https://www.rapid7.com/db/)
* [Searchsploit](https://www.exploit-db.com/searchsploit)
* [SecList](https://github.com/danielmiessler/SecLists)
* [Static Analysis](https://github.com/analysis-tools-dev/static-analysis)
* [W3AF](http://docs.w3af.org/en/latest/index.html)
* [WFuzz](https://wfuzz.readthedocs.io/en/latest/)
* [WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
* [XSS Attack Examples](https://www.thegeekstuff.com/2012/02/xss-attack-examples/?utm_source=tuicool)
* [ZAP + Burp Suite](https://www.youtube.com/watch?v=HlSfYRUE6E8)
* [ZAP + ZAP HUD](https://www.youtube.com/watch?v=7WL-emt5PDc)
* [ZAP Webswing](https://www.zaproxy.org/docs/docker/webswing/)



## Exploitation

The exploitation phase of a penetration test focuses solely on establishing access to a system or resource by bypassing security restrictions. During exploitation, deficiencies identified during vulnerability analysis are utilized to plan and conduct a precision strike. The primary focus is to identify the main entry point into the device or organization and to identify high value target assets. 

* [CSRF PoC Generator](https://github.com/merttasci/csrf-poc-generator)
* [Checksec.sh](http://www.trapkit.de/tools/checksec.html)
* [Corelan: Jumping to Shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
* [Corelan: Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
* [Exploit DB](https://www.exploit-db.com/)
* [File Signatures](https://www.garykessler.net/library/file_sigs.html)
* [GTFOBins](https://gtfobins.github.io/)
* [Hydra Login Pages](https://le4ker.me/tech/2017/04/04/hydra.html)
* [LOLBAS](https://lolbas-project.github.io/)
* [Metasploit Database](https://www.offensive-security.com/metasploit-unleashed/using-databases/)
* [Metasploit and beEF](http://wg135.github.io/blog/2017/06/26/beef-and-metasploit/)
* [Ngrok](https://ngrok.com/)
* [NoSQLmap](https://github.com/codingo/NoSQLMap)
* [Packet Storm Exploit Files](https://packetstormsecurity.com/files/tags/exploit/)
* [PoC in Github](https://github.com/nomi-sec/PoC-in-GitHub)
* [Powersploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) 
* [PwnTools](http://docs.pwntools.com/en/stable/intro.html)
* [SQL Injection](http://wg135.github.io/blog/2016/02/20/pentesterlab-web-for-pentester-sql-injection/)
* [SQLmap](http://sqlmap.org/)
* [Searchsploit](https://www.exploit-db.com/searchsploit)
* [Veil](https://github.com/Veil-Framework/Veil)
* [Webhook.site (repository)](https://github.com/fredsted/webhook.site)
* [Webhook.site](https://webhook.site/)
* [XSS Payload List](https://github.com/payloadbox/xss-payload-list)
* [XSS Payloads](http://www.xss-payloads.com/tools-list.html?o#category=online)

### Privilege Escalation

* [Bangenum](https://github.com/bngr/OSCP-CTF-Scripts/blob/master/bangenum.sh)
* [JAWS](https://github.com/411Hall/JAWS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) 
* [WESNG](https://github.com/bitsadmin/wesng)
* [Watson](https://github.com/rasta-mouse/Watson)
* [Windows Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

  

## Post Exploitation

The purpose of the Post-Exploitation phase is to determine the value of the compromised system and to maintain control of the machine for later use. The value of the machine is determined by the sensitivity of the data stored on it and the machine’s usefulness in further compromising the network.

* [Empire](https://github.com/EmpireProject/Empire)

### Passwords

* [CeWL](https://tools.kali.org/password-attacks/cewl)
* [Cmd5](https://www.cmd5.org/)
* [Crack SH](https://crack.sh/)
* [CrackStation](https://crackstation.net/)
* [Cracking Passwords 101](http://www.adeptus-mechanicus.com/codex/crkpass/crkpass.php)
* [Crackpot](http://cracker.offensive-security.com/)
* [Crunch](https://tools.kali.org/password-attacks/crunch)
* [Default Password Lookup](https://www.fortypoundhead.com/tools_dpw.asp)
* [Encryption Description](https://asecuritysite.com/encryption/)
* [Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
* [Ferdecode](https://asecuritysite.com/encryption/ferdecode)
* [GPUHASH ME](https://gpuhash.me/)
* [Hases.org](https://hashes.org/index.php)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)
* [Online Hash Tools](https://emn178.github.io/online-tools/)
* [Online Password Recovery](https://passwordrecovery.io/)
* [Pwning WordPress Passwords](https://medium.com/bugbountywriteup/pwning-wordpress-passwords-2caf12216956)
* [TunnelsUP: Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)

### Upload/Exfiltration

* [DNSCat2](https://github.com/iagox86/dnscat2)
* [From Kali to Windows](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
* [HTTP Tunneling](https://github.com/larsbrinkhoff/httptunnel)
* [Pyftplib](https://pyftpdlib.readthedocs.io/en/latest/install.html)
* [SBD](https://gitlab.com/kalilinux/packages/sbd)
* [Uuedecode](https://linux.die.net/man/1/uudecode)
* [Windows Port Forwarding](http://woshub.com/port-forwarding-in-windows/)

### Pivoting

* [PortFwd](https://www.offensive-security.com/metasploit-unleashed/portfwd/)
* [ProxyTunnels](https://www.offensive-security.com/metasploit-unleashed/proxytunnels/)



## Reporting

* [CVE Details](https://www.cvedetails.com/)
* [CVSS Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [MITRE CAPEC](https://capec.mitre.org/)
* [MITRE CVE](https://cve.mitre.org/index.html)
* [MITRE CWE](https://cwe.mitre.org/index.html)
* [Magic Tree](https://www.gremwell.com/magictreedoc/9df1fc54.html)
* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
* [OWASP Community Pages](https://owasp.org/www-community/)
* [Public Pentesting Reports](https://github.com/juliocesarfort/public-pentesting-reports)



## Cheat Sheets & References

#### Awesomelists

* [Awesome Open Source (OSINT)](https://awesomeopensource.com/project/blaCCkHatHacEEkr/OSINT_TIPS)
* [Awesome Penetration Testing](https://github.com/coreb1t/awesome-pentest-cheat-sheets)
* [Awesome Read Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)

#### Cheatsheets

* [Google Guide](http://www.googleguide.com/print/adv_op_ref.pdf)
* [HTML5 Security](http://html5sec.org/)
* [HTTPS Cheat Sheet](https://scotthelme.co.uk/https-cheat-sheet/)
* [Hashcat](https://github.com/frizb/Hashcat-Cheatsheet)
* [Hausec Pentesting Cheatsheet](https://hausec.com/pentesting-cheatsheet/) 
* [MSFconsole](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)
* [Netcat](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
* [Network Security Tools](https://sectools.org/)
* [Nikto](https://redteamtutorials.com/2018/10/24/nikto-cheatsheet/)
* [Nmap Reference Guide](https://nmap.org/book/man.html)
* [OWASP Attacks](https://owasp.org/www-community/attacks/)
* [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries/blob/master/Index.md)
* [OpenSSL commands](https://www.freecodecamp.org/news/openssl-command-cheatsheet-b441be1e8c4a/)
* [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)
* [Penetration Testing Execution Standard (PTES)](http://www.pentest-standard.org/index.php/Main_Page)
* [Penetration Testing Methodology](http://www.0daysecurity.com/pentest.html)
* [Reserved IPv4 Addresses](https://en.wikipedia.org/wiki/Reserved_IP_addresses)
* [SANS Internet Storm Center](https://isc.sans.edu/)
* [SANS: Metasploit](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)
* [SQLi](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* [SSH Tricks](https://serversforhackers.com/c/ssh-tricks)
* [SSRF Prevention](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)
* [SSRF](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf)
* [Security Design Patterns (Black Hat)](https://www.blackhat.com/presentations/bh-federal-03/bh-fed-03-peterson-up.pdf)
* [Security Design Patterns](https://sites.google.com/site/designpatternswiki/SecurityDesignPatterns/input-validator-pattern)
* [Seven Second Subnetting](https://www.youtube.com/watch?v=ZxAwQB8TZsM)
* [TCPDump](https://www.andreafortuna.org/2018/07/18/tcpdump-a-simple-cheatsheet/)
* [Testing Tools - OWASP](https://www.owasp.org/index.php/Appendix_A:_Testing_Tools#Testing_for_JavaScript_Security.2C_DOM_XSS)
* [Tom's Network Notes](http://tomax7.com/anetplus/index.htm)
* [VRT Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
* [Windows Privilege Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
* [Wireshark Display Filters](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf)

#### High on Coffee

* [Cheatsheet for HackTheBox](https://gist.github.com/AvasDream/47f13a510e543009a50c8241276afc24)
* [Fully Interactive TTY Upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
* [HighOn.Coffee](https://highon.coffee/)
* [LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Linux Commands Cheat Sheet](https://highon.coffee/blog/linux-commands-cheat-sheet/)
* [Nbtscan Cheat Sheet](https://highon.coffee/blog/nbtscan-cheat-sheet/)
* [Nmap Cheat Sheet](https://highon.coffee/blog/nmap-cheat-sheet/)
* [Penetration Testing Tools Cheat Sheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
* [Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [Systemd Cheat Sheet](https://highon.coffee/blog/systemd-cheat-sheet/)

#### Pentest Monkey (Security Warning)

* [Informix SQLi](http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet)
* [John The Ripper Hash Formats](http://pentestmonkey.net/cheat-sheet/ssh-cheat-sheet)
* [MSSQLi](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* [MySQL SQLi](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
* [Oracle SQLi](http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
* [Postgres SQLi](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
* [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [SSH Cheat Sheet](http://pentestmonkey.net/cheat-sheet/ssh-cheat-sheet)



## Manuals

* [Advanced Bashed Scripting](https://tldp.org/LDP/abs/html/)
* [Explainshell](https://explainshell.com/)
* [ICMP Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
* [MergeCAP](https://www.wireshark.org/docs/man-pages/mergecap.html)
* [Nikto](https://cirt.net/nikto2-docs/)
* [Nmap Scripting Engine](https://nmap.org/book/nse.html) 
* [Pure Bash Bible](https://github.com/dylanaraps/pure-bash-bible) 
* [SS64](https://ss64.com/)
* [TCP/IP Handbook](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)
* [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
* [XSS Payloads](http://www.xss-payloads.com/documentation.html)



## Guides

* [Abatchy: Port Forwarding](https://www.abatchy.com/2017/01/port-forwarding-practical-hands-on-guide)
* [Attacking & Securing FTP Servers](https://www.blackhat.com/presentations/bh-asia-02/bh-asia-02-beale-unix.pdf)
* [Bash Hackers Wiki](https://wiki.bash-hackers.org/doku.php)
* [Checkmate](https://niiconsulting.com/checkmate/2017/06/a-detail-guide-on-oscp-preparation-from-newbie-to-oscp/)
* [Command Line Fu](https://www.commandlinefu.com/commands/browse)
* [Command Line King Fu](http://blog.commandlinekungfu.com/p/index-of-tips-and-tricks.html)
* [Double Pivoting](https://pentest.blog/explore-hidden-networks-with-double-pivoting/)
* [Empire](https://alpinesecurity.com/blog/empire-a-powershell-post-exploitation-tool/)
* [Encrypted Bind & Revers Shells with Socat](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/)
* [Hacking Tutorials](https://www.hackingtutorials.org/)
* [Hacksplaining](https://www.hacksplaining.com/lessons)
* [IP Spoofing](https://security.stackexchange.com/questions/55279/how-easy-is-it-really-to-do-ip-spoofing)
* [Metastploit File Inclusion](https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/)
* [Netcat](https://nmap.org/ncat/guide/)
* [OSSTMM 3](https://www.isecom.org/OSSTMM.3.pdf)
* [OWASP: Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
* [Rapid7 msfvenom guide](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
* [SSH Tunneling](https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/)
* [SSRF](https://hackerone.com/reports/223203)
* [Severless for Pentesters](https://blog.ropnop.com/serverless-toolkit-for-pentesters/)
* [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
* [Tmux](https://linuxize.com/post/getting-started-with-tmux/)
* [Tunneling](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)
* [Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)



## Tutorials

* [Amass Extensive Tutorial](https://www.dionach.com/en-us/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [Bob1Bob2: Pentesterlab](http://wg135.github.io/blog/categories/pentesterlab/)
* [Bob1Bob2: beEF and metasploit](http://wg135.github.io/blog/2017/06/26/beef-and-metasploit/)
* [Creating Metasploit Payloads](https://netsec.ws/?p=331)
* [Daya: Windows Privilege Escalation](https://daya.blog/2018/01/06/windows-privilege-escalation/)
* [Explained: addslashes() Versus mysql_real_escape_string()](http://shiflett.org/blog/2006/addslashes-versus-mysql-real-escape-string)
* [Exploiting weak folder permissions](http://www.greyhathacker.net/?p=738)
* [G0tmi1k: Basic Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Hacking Vision](https://hackingvision.com/)
* [Hakluke’s Practical hacking tips and tricks](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97)
* [Interesting LFI Method](https://diablohorn.com/2010/01/16/interesting-local-file-inclusion-method/)
* [It's the Little Things II](https://docs.google.com/presentation/d/1xgvEScGZ_ukNY0rmfKz1JN0sn-CgZY_rTp2B_SZvijk/edit#slide=id.g4052c4692d_0_0)
* [Kryptomux SSRF](https://www.youtube.com/watch?v=BBKlQvxo3xg)
* [OpenVAS](https://hackertarget.com/openvas-tutorial-tips/)
* [PentesterLab: CVE-2014-6271](https://pentesterlab.com/exercises/cve-2014-6271/course)
* [PentesterLab: Php include & Post Exploitation](https://pentesterlab.com/exercises/php_include_and_post_exploitation/course)
* [PentesterLab: SQLi to shell](https://pentesterlab.com/exercises/from_sqli_to_shell_II/course)[PentesterLab: Linux Host Review](https://pentesterlab.com/exercises/linux_host_review/course)
* [PentesterLab: Web App Pentester - Directory Traversal](http://wg135.github.io/blog/2016/03/11/webforpentester-dir-traversal/)
* [PentesterLab: Web App Pentester I](https://pentesterlab.com/exercises/web_for_pentester/course)
* [PentesterLab: Web App Pentester II](https://pentesterlab.com/exercises/web_for_pentester_II/course)
* [PentesterLab: Web App Pentester - III](http://f4l13n5n0w.github.io/blog/2015/05/23/pentesterlab-web-for-pentester-final/)
* [PentesterLab: Web for Pentester - SQL Injection | Bob1Bob2](http://wg135.github.io/blog/2016/02/20/pentesterlab-web-for-pentester-sql-injection/)
* [Pentestmonkey: Unix Privilege Escalation](http://pentestmonkey.net/tools/audit/unix-privesc-check)
* [PwnTools & ROP](https://www.hackthezone.com/wp-content/uploads/2019/11/Weaponizing-ROP-with-PwNtools-ANDREI-GRIGORAS-18oct2019HTZ.pdf)
* [Regex: Regularly Exploitable](https://nvisium.com/blog/2015/06/11/regex-regularly-exploitable.html)
* [SQLi by Example](http://www.unixwiz.net/techtips/sql-injection.html)
* [SSRF - Exploiting URL Parsers](https://www.youtube.com/watch?v=D1S-G8rJrEk)
* [Scan for shellshock](http://edge-security.blogspot.com/2014/10/scan-for-shellshock-with-wfuzz.html)
* [W3AF Vulnerability Scan](https://www.youtube.com/watch?v=BuldIS7q_J0)
* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
* [Windows Privilege Escalation Methods](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
* [YouTube: OSCP VulnHub Series](https://www.youtube.com/playlist?list=PLK5YOQDpZKK2GtfxOHw9LQZl3z_f74EoR)



## Other

* [A Unix Person's Guide to Powershell](https://devops-collective-inc.gitbook.io/a-unix-person-s-guide-to-powershell/about)
* [Crontab Guru](https://crontab.guru/#*_*_*_*_*)
* [Docker Pentest Lab](https://github.com/etadata/owasp-workshop/blob/master/docker/docker-penetest-lab.md)
* [Five powershell symbols you should know](https://d12vzecr6ihe4p.cloudfront.net/media/965959/wp-five-simple-symbols-you-should-know-to-unlock-your-powershell-potential.pdf)
* [G0tmi1k Repositories](https://github.com/g0tmi1k?tab=repositories)
* [Guide to Vulnhub](https://medium.com/@gavinloughridge/a-beginners-guide-to-vulnhub-part-1-52b06466635d)
* [HackTheBox OSCP Preparation](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/)
* [LANMaster53 Projects](https://www.lanmaster53.com/projects/)
* [Linux Permissions Calculator](http://permissions-calculator.org/)
* [NVD Tools](https://github.com/facebookincubator/nvdtools)
* [PBcopy](https://superuser.com/questions/288320/whats-like-osxs-pbcopy-for-linux)
* [PowerShell equivalents for common BASH commands](https://mathieubuisson.github.io/powershell-linux-bash/)
* [Powershell: The many ways to use regex](https://powershellexplained.com/2017-07-31-Powershell-regex-regular-expression/)
* [Reddit OSCP Preparation](https://www.reddit.com/r/oscp/search?q=prepare&restrict_sr=1)
* [Risk Quantification](https://github.com/Netflix-Skunkworks/riskquant)
* [Sci-Hub](http://sci-hub.tw/)
* [Stanford Larget Network Dataset Collection](https://snap.stanford.edu/data/)
* [Teaching Secure Web Development](http://www.csis.pace.edu/~lchen/sweet/)
* [Web Security Academy](https://portswigger.net/web-security/all-labs)
* [Windows Security Updates API](https://github.com/Microsoft/MSRC-Microsoft-Security-Updates-API)



## Entertainment

* [Codename Generator](https://www.codenamegenerator.com/)
* [Fakeupdate](https://fakeupdate.net/)
* [Jargon File](http://www.catb.org/jargon/html/)
* [The Tao of Programming](https://www.mit.edu/~xela/tao.html)
* [Unix Koans](http://www.catb.org/~esr/writings/unix-koans/)
* [Vice/Cybersecurity](https://www.vice.com/en/topic/cybersecurity) 



## Threat Hunting (Bonus)

* [ADHD](https://www.activecountermeasures.com/free-tools/adhd/)
* [Atomic Red Team](https://atomicredteam.io/)
* [Blocking bad ICMP Messages](https://www.techrepublic.com/article/prevent-hacker-probing-block-bad-icmp-messages/)
* [Bro Cheat Sheets](https://github.com/corelight/bro-cheatsheets)
* [Canarytokens](https://docs.canarytokens.org/guide/)
* [Cobalt Strike](https://www.cobaltstrike.com/)
* [Cyber Wardog Lab](https://cyberwardog.blogspot.com/2017/02/setting-up-pentesting-i-mean-threat.html)
* [Fast Flux](https://en.wikipedia.org/wiki/Fast_flux)
* [JPCERTCC/LogonTracer](https://github.com/JPCERTCC/LogonTracer)
* [Kippo: SSH Honeypot](https://github.com/desaster/kippo)
* [Logging Made Easy](https://www.ncsc.gov.uk/blog-post/logging-made-easy)
* [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
* [Packet Total](https://packettotal.com/)
* [Public PCAP Files](https://www.netresec.com/?page=pcapfiles)
* [Rscript](https://linux.die.net/man/1/rscript)
* [Security Onion](https://securityonionsolutions.com/software)
* [Zeek](https://zeek.org/)

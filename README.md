# Hardening_security_on_Linux
Basic to advanced practices in hardening security in Linux

* Security Checklist - 1 
1. Ensure Physical Security. 

2. BIOS Protection. 

3. Disable Booting from external media devices. 

4. Boot Loader Protection. 

5. Keep the OS updated (only from trusted sources). 

6. Check the installed packages and remove the unnecessary ones. 

7. Check for Open Ports and stop unnecessary services. 

8. Enforce Password Policy. 

9. Audit Passwords using John the Ripper. 

10. Eliminate unused and well-known accounts that are not needed. 

11. Give users limited administrative access. 

12. Do not use the root account on a regular basis and do not allow direct root login. Master Linux Administration By Andrei Dumitrescu Security Checklist - 2 

13. Set limits using the ulimit command to avoid DoS attacks such as launching a fork bomb. 

14. Set proper file permissions. a. Audit the Set User ID (SUID) and Set Group ID (SGID) binaries on the system. b. Do not mount remote filesystems with root read-write access. Read-only access would be enough. c. Set the sticky bit on any world-writable directories. d. harden /tmp – mount it on a separate partition (not to fill all the disk space), mount it with noexec,nosuid bits set. 

15. Implement File Monitoring (Host IDS - AIDE). 

16. Scan for Rootkits, Viruses, and Malware (Rootkit Hunter, chkrootkit, ClamAV). 

17. Use Disk Encryption to protect your data. Don’t forget to encrypt your Backups as well. 

18. Secure every Network Service especially SSHd. Master Linux Administration By Andrei Dumitrescu Security Checklist - 3 

19. Scan your Network and Hosts using Nmap. 

20. Securing Your Linux System with a Firewall (Netfilter/Iptables). 

21. Monitor the firewall and its logs. 

22. Monitor your logs and search for suspicious activity (logwatch). 

23. Scan your servers using a VAS such as Nessus or OpenVAS. 

24. Make backups and test them.		


OPEN SSH CLIENT.
 		 
Installing OpenSSH (client and server)
 	  
Ubuntu
 		
sudo apt update && sudo apt install openssh-server openssh-client
		 
CentOS
 		
sudo dnf install openssh-server openssh-clients
 		
connecting to the server
  
ssh -p 22 username@server_ip # => Ex: ssh -p 2267 john@192.168.0.100
	
ssh -p 22 -l username server_ip
  
ssh -v -p 22 username@server_ip # => verbose
		 
2. Controlling the SSHd daemon
checking its status

sudo systemctl status ssh # => Ubuntu

sudo systemctl status sshd # => CentOS
 		 
stopping the daemon

sudo systemctl stop ssh # => Ubuntu

sudo systemctl stop sshd # => CentOS
 		 
restarting the daemon

sudo systemctl restart ssh # => Ubuntu

sudo systemctl restart sshd # => CentOS
 		 
enabling at boot time

sudo systemctl enable ssh # => Ubuntu

sudo systemctl enable sshd # => CentOS
 		 
sudo systemctl is-enabled ssh # => Ubuntu

sudo systemctl is-enabled sshd # => CentOS
 		 
3. Securing the SSHd daemon

change the configuration file (/etc/ssh/sshd_config) and then restart the server

man sshd_config
 		 
a) Change the port

Port 2278
 		 
b) Disable direct root login

PermitRootLogin no
 		 
c) Limit Users’ SSH access

AllowUsers stud u1 u2 john
 		 
d) Filter SSH access at the firewall level (iptables)
 		 
e) Activate Public Key Authentication and Disable Password Authentication
 		 
f) Use only SSH Protocol version 2
 		 
g) Other configurations:

ClientAliveInterval 300

ClientAliveCountMax 0
MaxAuthTries 2

MaxStartUps 3

LoginGraceTime 20



Boot Sequence Order 

1. BIOS executes MBR (Master Boot Record). 

2. MBR executes GRUB2. 

3. GRUB2 loads the kernel. 

4. The kernel executes systemd which initialize the system. 

SECURITY CHECKLIST: 

1. Physical Security (Kensington lock etc). 

2. Set up a BIOS password. 

3. Configure the system to boot automatically from the Linux partition. 

4. Set up a password for GRUB

locking password authentication

sudo passwd -l USERNAME

sudo password --lock USERNAME
		 
checking the account status

sudo passwd --status USERNAME

sudo chage -l USERNAME
 		 
unlocking password authentication

sudo passwd -u USERNAME
 		 
disable an account completely

sudo usermod --expiredate 1 tux

sudo usermod --expiredate 1970-01-02 tux
                  
Account never expires

sudo usermod —expiredate “” tux
 		 
checking the account expiration date

sudo chage -l tux

To check users in sudo group

Grep sudo /etc/group

To become temp root for 15mins

sudo su

If you need password to be asked for

sudo -k

Configuration file for sudo users 

Cat  /etc/sudoers

1 2 3 4 root ALL= (ALL:ALL) ALL tux ALL= (root) /bin/cp,/bin/ls,/usr/bin/vim,!/usr/bin/vim /etc/shadow dan ALL= NOPASSWD:ALL john ALL= NOPASSWD:/bin/cat,/usr/bin/updatedb,PASSWD:/bin/rm, NOEXEC:/bin/less %sudo ALL= (ALL:ALL) ALL %team ALL= (root) /usr/bin/apt update

ulimit -u

ulimit -a

sudo vim /etc/security/limits.conf

apt install John——John the ripper

CRACKING PASSWORD HASHES USING JOHN THE RIPPER
 		 
Installing JTR

apt install john
 		 
combining /etc/passwd and /etc/shadow in a single file

unshadow /etc/passwd /etc/shadow > unshadowed.txt
 		 
cracking in single mode

john -single unshadowed.txt
 		 
brute-force and dictionary attack

john --wordlist=/usr/share/john/password.lst --rules unshadowed.txt
 		 
dictionary files:

/usr/share/dict

/usr/share/metasploit-framework/data/wordlists # -> on Kali Linux
 		 
showing cracked hashes (~/.john/john.pot)

john --show unshadowed.txt
 		 
to continue an interrupted (ctrl+c) session, run in the same directory:

john -restore

cracking only accounts with specific shells (valid shells)

john --wordlist=mydict.txt --rules --shell=bash,sh unshadowed.txt
 		 
cracking only some accounts

john --wordlist=mydict.txt --rules --users=admin,mark unshadowed.txt
 		 
cracking in incremental mode (/etc/john/john.conf)

john --incremental unshadowed.txt


INSTALLING AIDE

apt update && apt install aide

aide -v
 		 
getting help

aide --help
 		 
/etc/aide/aide.conf # => config file
 		 
SEARCHING FOR CHANGES
 		 
initializing the AIDE database => /var/lib/aide/aide.db.new

aideinit
 		 
moving the db to the one that will be checked by AIDE

mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
		 
creating a runtime config file => /var/lib/aide/aide.conf.autogenerated

update-aide.conf # this is a command to run
 		 
DETECTING CHANGES

aide -c /var/lib/aide/aide.conf.autogenerated --check > report.txt
 		 
updating the db

aide -c /var/lib/aide/aide.conf.autogenerated --update

COPYING THE NEWLY CREATED DATABSE AS THE BASELINE DATABASE

cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
 		 
CREATING A CUSTOM aide.conf FILE (Example: /root/aide.conf) ##

database_in=file:/var/lib/aide/aide.db

database_out=file:/var/lib/aide/aide.db.new

MYRULE=u+g+p+n+s+m+sha256

/etc MYRULE

/usr MYRULE

/root MYRULE

!/usr/.*

!/usr/share/file$
		 
initializing the new AIDE db

aide -c /root/aide.conf --init
 		 
moving the new db to the baseline db

mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
		 
checking for any changes
aide -c /root/aide.conf --check

ROOTKITS

A rootkit is a collection of malicious computer software designed to enable access to a computer that is not otherwise allowed. After a successful intrusion into a system, usually the intruder will install a so-called "rootkit" to secure further access. 

Rootkit detection is difficult because a rootkit may be able to subvert the software that is intended to find it (rootkit scanners, antivirus). 

NEVER TRUST A COMPROMISED MACHINE. PERIOD 

Rootkit Scanners: 

1. Rootkit Hunter (rkhunter) rkhunter --check 

2. chkrootkit chkrootkit -q

INSTALLING RKHUNTER

apt update && apt install rkhunter
 		 
updating its data file of stored values with the current values

rkhunter --propupd
 		 
running a full system check

rkhunter --check # => /var/log/rkhunter.log

rkhunter --check --report-warnings-only
 		 
 		 
INSTALLING CHKROOTKIT

apt install chkrootkit
 		 
running a scan

chkrootkit

chkrootkit -q

INSTALLING CLAMAV

sudo apt install && sudo apt install clamav clamav-daemon
		 
checking the status

systemctl status clamav-freshclam

systemctl status clamav-daemon
 		 
starting the clamav daemon

systemctl start clamav-daemon
 		 
enabling the daemon to start and boot

systemctl enable clamav-daemon
 		 
getting a test virus

wget www.eicar.org/download/eicar.com
 		 
scanning a directory using clamdscan

clamdscan --fdpass /root/
 		 
moving found viruses to a quarantine directory

clamdscan --move=/quarantine --fdpass /root
 		 
scanning a directory using clamscan

clamscan --recursive /etc

clamscan --recursive --infected /quarantine

clamscan --recursive --infected --remove /quarantine/

FULL DISK ENCRYPTION
 		 
1. installing cryptsetup & dm-crypt

apt install cryptsetup
 		 
2. Idenfity the name of the disk or partition to encrypt:

fdisk -l # for this example it will be /dev/sdc
or
dmesg # for usb sticks
 		 
3. Filling the disk or partition to encrypt with random data (optional)

dd if=/dev/urandom of=/dev/sdc status=progress
 		 
4. Initialize the LUKS partition and set the initial passphrase

cryptsetup -y -v luksFormat /dev/sdc
		
WARNING!

This will overwrite data on /dev/sdc irrevocably.
 		
Are you sure? (Type uppercase yes): YES

Enter passphrase for /dev/sdc:

Verify passphrase:

Command successful.
 		 
5. Open the encrypted device and set up a mapping name

cryptsetup luksOpen /dev/sdc secretdata

ls -l /dev/mapper
 		 
Display the status of the mapping file

cryptsetup status secretdata
 		 
6. Format the filesystem

mkfs.ext4 /dev/mapper/secretdata
 		 
7. Mount the encrypted file system into the main file tree.

mount /dev/mapper/secretdata /mnn # -> you can mount it to any existing directory like /mnt
 		 
8. Unmount the encrypted disk

umount /mnt

cryptsetup luksClose secretdata
		 
9. Accesing the encrypted disk after a restart or unmounting:

cryptsetup luksOpen /dev/hdc secretdata

mount /dev/mapper/secretdata /root/secret
 		 
10. Unlocking LUKS Encrypted Drives With A Keyfile
 		 
generating a random keyfile

dd if=/dev/urandom of=/root/keyfile bs=1024 count=4
 		 
set the permissions (only root can read it)

chmod 400 /root/keyfile
		 
add the keyfile as an additional authorization method

cryptsetup luksAddKey /dev/sdc /root/keyfile
 		 
unlock the drive using the keyfile

cryptsetup luksOpen /dev/hdc secret --key-file /root/keyfile


gpg -c filename.txt

gpg -c secret.txt

a new file with.gpg extension will be created and when you cat the file, it shows gibberish

gpg —version

man gpg-agent

EncryptPAD 

OpenSource text editor with an encryption function. 

Portable: simply copy the executable to a memory stick and use it. 

Multi-platform: it works on Windows, Linux, MacOS. 

Double protection: randomly generated key files in addition to passphrases. 

Very secure: It uses AES for symmetric encryption and SHA256 for integrity check.

Steganography Explained 

Steganography is the art of hiding secret information in plain-text or in clear-sight. 

Steganographic tools can easily embed secret files into images, movies, audio files or other file formats. 

The word steganography comes from the Greek word “steganos” which means “hidden” and “graph” or “graphia” which means writing. The purpose of steganography is to hide even the mere existence of the message that is being sent. 

Steps: 

1. The secret file is encrypted. 

2. The encrypted secret file is embedded into a cover file according to a steganographic algorithm. The cover file that contains the secret message or the embedded file is called stego file. 

3. The stego file is sent normally (in clear-text or encrypted) to the destination or is made public to be easily reached. 

Steganography Use-Cases 

Sending encrypted messages without raising suspicion, such as in countries where free speech is suppressed. 

Digital watermark of the copyright holder. 

Hiding or transporting secret information (secret documents, Bitcoin private key etc). 

Transporting sensitive data from point A to point B such that the transfer of the data is unknown.

STEGANOGRAPHY
 		 
installing steghide

apt update && apt install steghide
 		 
embedding a secret file into a cover file

steghide embed -ef secret.txt -cf cat.jpg

Enter passphrase:

Re-Enter passphrase:

embedding "secret.txt" in "cat.jpg"... done
 		 
getting info about a cover/stego file

steghide info cat.jpg

"cat.jpg":

format: jpeg

capacity: 47.5 KB

Try to get information about embedded data ? (y/n) n
		 
extracting the secret file from the stego file

steghide extract -sf cat.jpg

Enter passphrase:

wrote extracted data to "secret.txt".

NMAP NMAP is a network discovery and security auditing tool. 

TCP Scans: ○ SYN Scan: -sS (root only) ○ Connect Scan: -sT 

UDP Scan: -sU 

ICMP Scan: -sn or -sP 

Example: nmap -sS -p 22,100 -sV 192.168.0.1

 		## NMAP
 		 
SCAN ONLY YOUR OWN HOSTS AND SERVERS !!! 

Scanning Networks is your own responsibility ##
 		 
Syn Scan - Half Open Scanning (root only)

nmap -sS 192.168.0.1
 		 
Connect Scan

nmap -sT 192.168.0.1
 		 
Scanning all ports (0-65535)

nmap -p- 192.168.0.1
 		 
Specifying the ports to scan

nmap -p 20,22-100,443,1000-2000 192.168.0.1
 		 
Scan Version

nmap -p 22,80 -sV 192.168.0.1
 		 
Ping scanning (entire Network)

nmap -sP 192.168.0.0/24
 		 
Treat all hosts as online -- skip host discovery

nmap -Pn 192.168.0.101
 		 
Excluding an IP

nmap -sS 192.168.0.0/24 --exclude 192.168.0.10
 		 
Saving the scanning report to a file

nmap -oN output.txt 192.168.0.1
 		 
OS Detection

nmap -O 192.168.0.1
 		 
Enable OS detection, version detection, script scanning, and traceroute

nmap -A 192.168.0.1
 		 
https://nmap.org/book/performance-timing-templates.html
 		 
-T paranoid|sneaky|polite|normal|aggressive|insane (Set a timing template)

These templates allow the user to specify how aggressive they wish to be, while leaving Nmap to pick the exact timing values. The templates also make some minor speed adjustments for which fine-grained control options do not currently exist.
 		 
-A OS and service detection with faster execution

nmap -A -T aggressive cloudflare.com
 		 
Using decoys to evade scan detection

nmap -p 22 -sV 192.168.0.101 -D 192.168.0.1,192.168.0.21,192.168.0.100
 		 
 		 
reading the targets from a file (ip/name/network separeted by a new line or a whitespace)

nmap -p 80 -iL hosts.txt
 		 
exporting to out output file and disabling reverse DNS

nmap -n -iL hosts.txt -p 80 -oN output.txt

Netfilter is software firewall for Linux and controlled by Iptables command.
Every Linux distribution uses net filter/iptables and nothing extra to install
Incoming traffic is filtered on the INPUT CHAIN of the filter table
Outgoing traffic is filtered on the OUTPUT CHAIN of the filter table
Routed traffic is filtered on the FORWARD CHAIN of the nat table
SNAT/MASQUERADE is performed on the POSTROUTING CHAIN of the nat table
Dat/pORT fORWARDING is performed on the PREROUTING CHAIN of the nat table
To modify values from the packets header add rules to the mangle table
To skip the connection tracking add rules with NOTRACK target to the raw table.

How to list all iptables rules on Linux
The procedure to list all rules on Linux is as follows:
1. Open the terminal app or login using ssh command: $ ssh user@server-name
2. To list all IPv4 rules: $ sudo iptables -S
3. Get list of all IPv6 rules: $ sudo ip6tables -S
4. To list all tables rules: $ sudo iptables -L -v -n | more
5. Just list all rules for INPUT tables: $ sudo iptables -L INPUT -v -n
6. $ sudo iptables -S INPUT
Let us see all syntax and usage in details to show and list all iptables rules on Linux operating systems.
Viewing all iptables rules in Linux
The syntax is:
iptables -S
iptables --list
iptables -L
iptables -S TABLE_NAME
iptables --table NameHere --list
iptables -t NameHere -L -n -v --line-numbers

Iptables -A OUTPUT -d www.ubutun.com -j DROP

fILTER BY tcp or UDP
Single
Iptables -A INPUT -p tcp —dport 22 -j DROP
Multiple
Iptables -A OUTPUT -p tcp -m multiport —dports 80,443 -j ACCEPT
Print all rules in the selected chain
The command syntax is as follows for IPv4 rules:
$ sudo iptables -S
$ sudo iptables -S INPUT
$ iptables -S OUTPUT

￼
 For IPv6 rules:
$ sudo ip6tables -S
$ sudo ip6tables -S INPUT
$ ip6tables -S OUTPUT
How to list rules for given tables
Type the following command as root user:
# iptables -L INPUT
# iptables -L FORWARD
# iptables -L OUTPUT
# iptables -L
# Listing IPv6 rules #
# ip6tables -L INPUT
# ip6tables -L FORWARD
# ip6tables -L OUTPUT
# ip6tables -L
 Sample outputs for IPv4:
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:domain
ACCEPT     udp  --  anywhere             anywhere             udp dpt:domain
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:bootps
ACCEPT     udp  --  anywhere             anywhere             udp dpt:bootps
ufw-before-logging-input  all  --  anywhere             anywhere            
ufw-before-input  all  --  anywhere             anywhere            
ufw-after-input  all  --  anywhere             anywhere            
ufw-after-logging-input  all  --  anywhere             anywhere            
ufw-reject-input  all  --  anywhere             anywhere            
ufw-track-input  all  --  anywhere             anywhere            
 
Chain FORWARD (policy DROP)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ufw-before-logging-forward  all  --  anywhere             anywhere            
ufw-before-forward  all  --  anywhere             anywhere            
ufw-after-forward  all  --  anywhere             anywhere            
ufw-after-logging-forward  all  --  anywhere             anywhere            
ufw-reject-forward  all  --  anywhere             anywhere            
ufw-track-forward  all  --  anywhere             anywhere            
 
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ufw-before-logging-output  all  --  anywhere             anywhere            
ufw-before-output  all  --  anywhere             anywhere            
ufw-after-output  all  --  anywhere             anywhere            
ufw-after-logging-output  all  --  anywhere             anywhere            
ufw-reject-output  all  --  anywhere             anywhere            
ufw-track-output  all  --  anywhere             anywhere            
.....
..
..
Chain ufw-user-limit (0 references)
target     prot opt source               destination         
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 5 LOG level warning prefix "[UFW LIMIT BLOCK] "
REJECT     all  --  anywhere             anywhere             reject-with icmp-port-unreachable
 
Chain ufw-user-limit-accept (0 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
 
Chain ufw-user-logging-forward (0 references)
target     prot opt source               destination         
 
Chain ufw-user-logging-input (0 references)
target     prot opt source               destination         
 
Chain ufw-user-logging-output (0 references)
target     prot opt source               destination         
 
Chain ufw-user-output (1 references)

target     prot opt source               destination

Let us try to understand rules output:

target – Tell what to do when a packet matches the rule. Typically, you ACCEPT or REJECT or DROP the packet. You can jump to another chain too.
 
prot – The protocol for rule.

opt – Additional options for rule.

source – The source IP address/subnet/domain name.

destination – The destination IP address/subnet/domain name.

How to see nat rules:

By default the filter table is used. To see NAT rules, enter:

iptables -t nat -L

Other table options:

iptables -t filter -L

iptables -t raw -L

iptables -t security -L

iptables -t mangle -L

iptables -t nat -L

ip6tables -t filter -L

How to see nat rules with line numbers:

Pass the --line-numbers option:

iptables -t nat -L --line-numbers -n

for IPv4 rules

ip6tables -t nat -L --line-numbers -n

Sample outputs for IPv4:

Chain PREROUTING (policy ACCEPT 28M packets, 1661M bytes)

num   pkts bytes target     prot opt in     out     source               destination 

1        0     0 DNAT       tcp  --  eth0   *       10.10.29.68          0.0.0.0/0            tcp dpt:3306 to:10.0.3.19:3306

2        0     0 DNAT       tcp  --  eth0   *       10.10.29.68          0.0.0.0/0            tcp dpt:11211 to:10.0.3.20:11211

3        0     0 DNAT       udp  --  eth0   *       10.10.29.68          0.0.0.0/0            udp dpt:11211 to:10.0.3.20:11211
 
Chain INPUT (policy ACCEPT 18M packets, 1030M bytes)

num   pkts bytes target     prot opt in     out     source               destination         
 
Chain OUTPUT (policy ACCEPT 23M packets, 1408M bytes)

num   pkts bytes target     prot opt in     out     source               destination         
 
Chain POSTROUTING (policy ACCEPT 33M packets, 1979M bytes)

num   pkts bytes target     prot opt in     out     source               destination    

1    38927 2336K MASQUERADE  all  --  *      *       10.0.3.0/24         !10.0.3.0/24  

2        0     0 MASQUERADE  all  --  *      *       10.0.3.0/24         !10.0.3.0/24

How to see nat rules with counters (bytes and packets)

Pass the -v option to iptables command to view all iptables rules on Linux:

# iptables -t nat -L -n -v


Linux viewing all iptables NAT, DNAT, MASQUERADE rules

Say hello to ip6tables

ip6tables is administration tool for IPv6 packet filtering and NAT. To see IPv6 tables, enter:

ip6tables -L -n -v

Chain INPUT (policy DROP 239 packets, 16202 bytes)

 pkts bytes target     prot opt in     out     source               destination 
 
 136K   30M ufw6-before-logging-input  all      *      *       ::/0                 ::/0   
 
 136K   30M ufw6-before-input  all      *      *       ::/0                 ::/0  
 
  241 16360 ufw6-after-input  all      *      *       ::/0                 ::/0 
  
  239 16202 ufw6-after-logging-input  all      *      *       ::/0                 ::/0  
  
  239 16202 ufw6-reject-input  all      *      *       ::/0                 ::/0    
  
  239 16202 ufw6-track-input  all      *      *       ::/0                 ::/0                

Chain FORWARD (policy DROP 483 packets, 32628 bytes)

 pkts bytes target     prot opt in     out     source               destination 
 
  483 32628 ufw6-before-logging-forward  all      *      *       ::/0                 ::/0   
  
  483 32628 ufw6-before-forward  all      *      *       ::/0                 ::/0   
  
  483 32628 ufw6-after-forward  all      *      *       ::/0                 ::/0   
  
  483 32628 ufw6-after-logging-forward  all      *      *       ::/0                 ::/0  
  
  483 32628 ufw6-reject-forward  all      *      *       ::/0                 ::/0      
  
  483 32628 ufw6-track-forward  all      *      *       ::/0                 ::/0                

Chain OUTPUT (policy ACCEPT 122 packets, 8555 bytes)

 pkts bytes target     prot opt in     out     source               destination    
 
 136K   30M ufw6-before-logging-output  all      *      *       ::/0                 ::/0   
 
 136K   30M ufw6-before-output  all      *      *       ::/0                 ::/0    
 
  183 14107 ufw6-after-output  all      *      *       ::/0                 ::/0   
  
  183 14107 ufw6-after-logging-output  all      *      *       ::/0                 ::/0   
  
  183 14107 ufw6-reject-output  all      *      *       ::/0                 ::/0      
  
  183 14107 ufw6-track-output  all      *      *       ::/0                 ::/0                

Chain ufw6-after-forward (1 references)

 pkts bytes target     prot opt in     out     source               destination         

...
....
..
 pkts bytes target     prot opt in     out     source               destination    
 
   19  1520 ACCEPT     tcp      *      *       ::/0                 ::/0                 ctstate NEW
   
   42  4032 ACCEPT     udp      *      *       ::/0                 ::/0                 ctstate NEW

Chain ufw6-user-forward (1 references)

 pkts bytes target     prot opt in     out     source               destination         

Chain ufw6-user-input (1 references)

 pkts bytes target     prot opt in     out     source               destination         

Chain ufw6-user-limit (0 references)

 pkts bytes target     prot opt in     out     source               destination   
 
    0     0 LOG        all      *      *       ::/0                 ::/0                 limit: avg 3/min burst 5 LOG flags 0 
level 4 prefix "[UFW LIMIT BLOCK] "
    0     0 REJECT     all      *      *       ::/0                 ::/0                 reject-with icmp6-port-unreachable

Chain ufw6-user-limit-accept (0 references)

 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all      *      *       ::/0                 ::/0                

Chain ufw6-user-logging-forward (0 references)

 pkts bytes target     prot opt in     out     source               destination         

Chain ufw6-user-logging-input (0 references)

 pkts bytes target     prot opt in     out     source               destination         

Chain ufw6-user-logging-output (0 references)

 pkts bytes target     prot opt in     out     source               destination         

Chain ufw6-user-output (1 references)

 pkts bytes target     prot opt in     out     source               destination         

 To see nat rules and line-numbers, enter:

iptables -t nat -L --line-numbers -nip6tables -L -n




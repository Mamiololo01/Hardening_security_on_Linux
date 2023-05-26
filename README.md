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

 
 
 ##########################
 		## OpenSSH
 		##########################
 		 
   1. Installing OpenSSH (client and server)
 	  
    Ubuntu
 		
    sudo apt update && sudo apt install openssh-server openssh-client
		 
 		# CentOS
 		
    sudo dnf install openssh-server openssh-clients
 		 
	 connecting to the server
  
  ssh -p 22 username@server_ip # => Ex: ssh -p 2267 john@192.168.0.100
	
  ssh -p 22 -l username server_ip
  
  ssh -v -p 22 username@server_ip # => verbose
		 
 		# 2. Controlling the SSHd daemon
 		# checking its status
 		sudo systemctl status ssh # => Ubuntu
 		sudo systemctl status sshd # => CentOS
 		 
 		# stopping the daemon
* 		sudo systemctl stop ssh # => Ubuntu
* 		sudo systemctl stop sshd # => CentOS
* 		 
* 		# restarting the daemon
* 		sudo systemctl restart ssh # => Ubuntu
* 		sudo systemctl restart sshd # => CentOS
* 		 
* 		# enabling at boot time
* 		sudo systemctl enable ssh # => Ubuntu
* 		sudo systemctl enable sshd # => CentOS
* 		 
* 		sudo systemctl is-enabled ssh # => Ubuntu
* 		sudo systemctl is-enabled sshd # => CentOS
* 		 
* 		# 3. Securing the SSHd daemon
* 		# change the configuration file (/etc/ssh/sshd_config) and then restart the server
* 		man sshd_config
* 		 
* 		a) Change the port
* 		Port 2278
* 		 
* 		b) Disable direct root login
* 		PermitRootLogin no
* 		 
* 		c) Limit Users’ SSH access
* 		AllowUsers stud u1 u2 john
* 		 
* 		d) Filter SSH access at the firewall level (iptables)
* 		 
* 		e) Activate Public Key Authentication and Disable Password Authentication
* 		 
* 		f) Use only SSH Protocol version 2
* 		 
* 		g) Other configurations:
* 		ClientAliveInterval 300
* 		ClientAliveCountMax 0
* 		MaxAuthTries 2
* 		MaxStartUps 3
* 		LoginGraceTime 20



Boot Sequence Order 
1. BIOS executes MBR (Master Boot Record). 
2. MBR executes GRUB2. 
3. GRUB2 loads the kernel. 
4. The kernel executes systemd which initialize the system. 

Security Checklist: 
1. Physical Security (Kensington lock etc). 
2. Set up a BIOS password. 
3. Configure the system to boot automatically from the Linux partition. 
4. Set up a password for GRUB

* 		# locking password authentication
* 		sudo passwd -l USERNAME
* 		sudo password --lock USERNAME
* 		 
* 		# checking the account status
* 		sudo passwd --status USERNAME
* 		sudo chage -l USERNAME
* 		 
* 		# unlocking password authentication
* 		sudo passwd -u USERNAME
* 		 
* 		# disable an account completely
* 		sudo usermod --expiredate 1 tux
* 		sudo usermod --expiredate 1970-01-02 tux
                  
                      Account never expires
                      Sudo usermod —expiredate “” tux
* 		 
* 		# checking the account expiration date
* 		sudo chage -l tux

To check users in sudo group
Grep sudo /etc/group

To become temp root for 15mins
Sudo su

If you need password to be asked for
Sudo -k

Configuration file for sudo users 
Cat  /etc/sudoers

1 2 3 4 root ALL= (ALL:ALL) ALL tux ALL= (root) /bin/cp,/bin/ls,/usr/bin/vim,!/usr/bin/vim /etc/shadow dan ALL= NOPASSWD:ALL john ALL= NOPASSWD:/bin/cat,/usr/bin/updatedb,PASSWD:/bin/rm, NOEXEC:/bin/less %sudo ALL= (ALL:ALL) ALL %team ALL= (root) /usr/bin/apt update

Ulimit -u
Ulimit -a
Sudo vim /etc/security/limits.conf

Apt install John——John the ripper
* 		CRACKING PASSWORD HASHES USING JOHN THE RIPPER
* 		 
* 		# Installing JTR
* 		apt install john
* 		 
* 		# combining /etc/passwd and /etc/shadow in a single file
* 		unshadow /etc/passwd /etc/shadow > unshadowed.txt
* 		 
* 		# cracking in single mode
* 		john -single unshadowed.txt
* 		 
* 		# brute-force and dictionary attack
* 		john --wordlist=/usr/share/john/password.lst --rules unshadowed.txt
* 		 
* 		# dictionary files:
* 		# /usr/share/dict
* 		# /usr/share/metasploit-framework/data/wordlists # -> on Kali Linux
* 		 
* 		# showing cracked hashes (~/.john/john.pot)
* 		john --show unshadowed.txt
* 		 
* 		# to continue an interrupted (ctrl+c) session, run in the same directory:
* 		john -restore
* 		 
* 		# cracking only accounts with specific shells (valid shells)
* 		john --wordlist=mydict.txt --rules --shell=bash,sh unshadowed.txt
* 		 
* 		# cracking only some accounts
* 		john --wordlist=mydict.txt --rules --users=admin,mark unshadowed.txt
* 		 
* 		# cracking in incremental mode (/etc/john/john.conf)
* 		john --incremental unshadowed.txt


* 		# installing AIDE
* 		apt update && apt install aide
* 		aide -v
* 		 
* 		# getting help
* 		aide --help
* 		 
* 		/etc/aide/aide.conf # => config file
* 		 
* 		### SEARCHING FOR CHANGES ###
* 		 
* 		# initializing the AIDE database => /var/lib/aide/aide.db.new
* 		aideinit
* 		 
* 		# moving the db to the one that will be checked by AIDE
* 		mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
* 		 
* 		# creating a runtime config file => /var/lib/aide/aide.conf.autogenerated
* 		update-aide.conf # this is a command to run
* 		 
* 		# detecting changes
* 		aide -c /var/lib/aide/aide.conf.autogenerated --check > report.txt
* 		 
* 		# updating the db
* 		aide -c /var/lib/aide/aide.conf.autogenerated --update
* 		# copying the newly created database as the baseline database
* 		cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
* 		 
* 		## CREATING A CUSTOM aide.conf FILE (Example: /root/aide.conf) ##
* 		database_in=file:/var/lib/aide/aide.db
* 		database_out=file:/var/lib/aide/aide.db.new
* 		MYRULE=u+g+p+n+s+m+sha256
* 		/etc MYRULE
* 		/usr MYRULE
* 		/root MYRULE
* 		!/usr/.*
* 		!/usr/share/file$
* 		 
* 		# initializing the new AIDE db
* 		aide -c /root/aide.conf --init
* 		 
* 		# moving the new db to the baseline db
* 		mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
* 		 
* 		# checking for any changes
* 		aide -c /root/aide.conf --check

Rootkits ● A rootkit is a collection of malicious computer software designed to enable access to a computer that is not otherwise allowed. ● After a successful intrusion into a system, usually the intruder will install a so-called "rootkit" to secure further access. ● Rootkit detection is difficult because a rootkit may be able to subvert the software that is intended to find it (rootkit scanners, antivirus). ● NEVER TRUST A COMPROMISED MACHINE. PERIOD Rootkit Scanners: 1. Rootkit Hunter (rkhunter) rkhunter --check 2. chkrootkit chkrootkit -q

* 		# installing rkhunter
* 		apt update && apt install rkhunter
* 		 
* 		# updating its data file of stored values with the current values
* 		rkhunter --propupd
* 		 
* 		# running a full system check
* 		rkhunter --check # => /var/log/rkhunter.log
* 		rkhunter --check --report-warnings-only
* 		 
* 		 
* 		# installing chkrootkit
* 		apt install chkrootkit
* 		 
* 		# running a scan
* 		chkrootkit
* 		chkrootkit -q

* 		# installing clamav
* 		sudo apt install && sudo apt install clamav clamav-daemon
* 		 
* 		# checking the status
* 		systemctl status clamav-freshclam
* 		systemctl status clamav-daemon
* 		 
* 		# starting the clamav daemon
* 		systemctl start clamav-daemon
* 		 
* 		# enabling the daemon to start and boot
* 		systemctl enable clamav-daemon
* 		 
* 		# getting a test virus
* 		wget www.eicar.org/download/eicar.com
* 		 
* 		# scanning a directory using clamdscan
* 		clamdscan --fdpass /root/
* 		 
* 		# moving found viruses to a quarantine directory
* 		clamdscan --move=/quarantine --fdpass /root
* 		 
* 		# scanning a directory using clamscan
* 		clamscan --recursive /etc
* 		clamscan --recursive --infected /quarantine
* 		clamscan --recursive --infected --remove /quarantine/


1. What is a GNU project?

GNU stands for GNU's not Unix. GNU project was announced by Richard Stallman with the purpose of developing a free and open source software so that everyone has the right to copy it, distribute it, study it or modify it. GNU project consisted of bootloader, daemon etc except the kernel. Linux developed by Linus Torvalds was the final part for the GNU project. The GNU project along with the Linux Kernel came to be the first free operating system commonly known as Linux.

2. What is the difference between Unix & Linux?

| Linux | Unix |
| - | - |
| Linux is open source and free operating system. Linux uses Gnome and other GUI. The default shell is bash. | Unix is licensed Operating System. It was initially developed as a command line operating system. The default shell is Bourne shell. |

3. What do you mean by Integrity check of BIOS? Mention firmwares other than BIOS

The system integrity test performed by BIOS is called POST(Power On Self Test). POST include routines performed by the firmware once the device is switched on to verify if the hardware is performing as expected otherwise return error messages and beeps. The harware checked include RAM, processors, peripheral devices etc.

UEFI is another firmware.


4. What is a UEFI?

The Unified Extensible Firmware Interface (UEFI), like BIOS (Basic Input Output System), is a firmware that runs when the computer is booted. It initializes the hardware and loads the operating system into the memory.

5. What is the difference between BIOS & UEFI?

* UEFI supports drive sizes upto 9 zettabytes, whereas BIOS only supports 2.2 terabytes.

* UEFI provides faster boot time.

* UEFI offers security like "Secure Boot", which prevents the computer from booting from unauthorized/unsigned applications.

* UEFI runs in 32bit or 64bit mode, whereas BIOS runs in 16bit mode. So UEFI is able to provide a GUI involving mouse as opposed to BIOS which allows navigation only using the keyboard.


6. When should you go for Ubuntu & when for other systems?

* Ubuntu: It is based on Debian. It has an elegant GUI and thus designed to help people who transitioned from windows or mac to Linux.
* Debian: Debain is the mother of distros. Ubuntu, Linux Mint are based on Debian. It has high stability and thus can be used in production servers.
* RHEL: Red Hat Enterprise Linux. It is designed for commercial and enterprise purposes. It has a paid support contract.
* Centos: It is based on Red Hat distro. Except it is free and does not provide the paid support contract.
* Fedora: Based on Red Hat distro. Has all the new features and updates and hence less stable.
* Kali Linux: Developed for pentration testing.

7. List various linux distributions & their use cases.

* Ubuntu: It is based on Debian. It has an elegant GUI and thus designed to help people who transitioned from windows or mac to Linux.
* Debian: Debain is the mother of distros. Ubuntu, Linux Mint are based on Debian. It has high stability and thus can be used in production servers.
* RHEL: Red Hat Enterprise Linux. It is designed for commercial and enterprise purposes. It has a paid support contract.
* Centos: It is based on Red Hat distro. Except it is free and does not provide the paid support contract.
* Fedora: Based on Red Hat distro. Has all the new features and updates and hence less stable.
* Kali Linux: Developed for pentration testing.

8. What does a systemd.unit(5) means?

Man Pages are divided into 8 sections.
* User Commands : Commands that can be run from the shell by a normal user
* System Calls: Programming functions used to make calls to the Linux kernel
* C Library Functions: Programming functions that provide interfaces to specific programming libraries.
* Devices and Special Files: File system nodes that represent hardware devices or software devices.
* File Formats and Conventions: The structure and format of file types or specific configuration files.
* Games: Games available on the system
* Miscellaneous: Overviews of miscellaneous topics such as protocols, filesystems and so on.
* System administration tools and Daemons:Commands that require root or other administrative privileges to use.


9. What are getty commands and uname command?

Uname Command- Uname Command is used for displaying the information about this system.
SYNTAX- uname [option]
OPTIONS-      
* -a: It prints all the system information in the following order: Kernel name, network node hostname, kernel release date, kernel version, machine hardware name, hardware platform, operating system
Syntax: $uname  -a
* -s: It prints the kernel name.
Syntax: $uname  -s

* -n: It prints the hostname of the network node (current computer).
Syntax: $uname  -n

* -r:  It prints the kernel release date.
Syntax: $uname  -r

* -v:  It prints the version of the current kernel.
Syntax: $uname  -v

* -m: It prints the machine hardware name.
Syntax: $uname  -m

* -p:  It prints the type of the processor.
Syntax: $uname  -p

* -i:   It prints the platform of the hardware.
Syntax: $uname  -i

* -o:  It prints the name of the operating system.
Syntax: $uname  -o

getty, short for "get tty", is a Unix program running on a host computer that manages physical or virtual terminals (TTYs). When it detects a connection, it prompts for a username and runs the 'login' program to authenticate the user.

11. What are /dev/loop and /dev/tty ?

dev/tty is a special file, representing the terminal for the current process.

dev/tty is a loop device file which is used to mount snaps and images.

12. What are Linux Signals?

A signal is an event generated by the UNIX and Linux systems in response to some condition. Upon receipt of a signal, a process may take action. A signal is just like an interrupt; when it is generated at the user level, a call is made to the kernel of the OS, which then acts accordingly. There are two types of signals:

Maskable: signals which can be changed or ignored by the user (e.g., Ctrl+C).
Non-Maskable: signals which cannot be changed or ignored by the user. These typically occur when the user is signaled for non-recoverable hardware errors.

13. What is the purpose of creating and using hidden files.

Files that exist on a computer, but don't appear when listing or exploring, are called hidden files. A hidden file is primarily used to help prevent important data from being accidentally deleted.

14. How ext4fs is faster/better?

Ext4 is faster because it supports delayed allocation. Delayed allcoation means a file is which is written, the appended part is stored in the memory like RAM or cache and after a time written to the hardisk. This time is called writeback time and hence multiple blocks are blocks at once reducing processor utilization.

Moreover, Ext4 file system marks the unallocated blocks. Hence during file system check this blocks are not checked.

15. What is swap & swap memory?

Swap is the hard disk space that is used to simulate extra memory. When the system is low on memory, it swaps a section of ram used by idle program to the hard disk. It involves extensive reading and writing on hard disk and thus is slow.

16. How to mount a file system?

To mount a file system, we use the mount command. We use the mount command with the file system and the mount point. The mount point becomes the root directory for the mounted file system.

17. Mention a ZFS use case.

Zettabyte file system is an advanced file system. It has pool storage and copy on write mechanism.

18. How to check the port number of a process?

`netstat -anp`

19. What is unix time sharing (UTS)?

It is a namespace which allows a same system to appear to processes with different hostname and different domain.

20. What are control groups?

A control group (cgroup) is a Linux kernel feature that limits, accounts for, and isolates the resource usage (CPU, memory, disk I/O, network, and so on) of a collection of processes.

21. What is the difference between sbin & usr/sbin?

Sbin contains the binaries of commands which require root priviledges. The /sbin directory under root directory is available for all the users and are used when a system is booted and the usr partition is not mounted.

usr/sbin contains binary files for the commands that requires root priviledges and which are user specific.

22. Examples of awk, grep and sed

Grep command is used for finding particular patterns in a file and to display all the fields matching that pattern.

Suppose we want to find a word name common in a file then we can do this by

grep -i "name" Name.txt (here i is used as to ignore case senstivity)

likewise we can use this grep command with different options

Awk command is more of scripting language used in manipulating data and generating reports.

When using ‘awk’ we enclose patterns in curly braces. Both pattern and action form a rule and the entire awk program is enclosed in single quotes.

awk '{print}' Name.txt (here since pattern is not specified it will print all)

awk '/name/ {print}' Name.txt

it will print lines containing name.

awk ‘NR==3, NR==6 {print NR,$0}’ Name.txt

It will display from line number 3 to number 6.

SED is short for stream editor. It can be used to perform different functions such as searching.

sed 's/manager/operations/g' example.txt

To replace only on a specific line, specify the file line as below where we are replacing on the third line.

sed '3 s/manager/operations/'g example.txt

here we wil also use i flag to save the file

sed -i s/manager/operations/'g example.txt

23. How many tables are there in iptables?

There are five tables in iptables:

* Packet FIltering Table 
  
  Filter Table is the default table, if there are no user defined tables this built-in table is used. The built-in chains for this tables are INPUT, OUTPUT and FORWARD.

* NAT Table

  Network Address Translation (NAT) Table is exactly what it contains, a table of network address translations; where each record in the table is a mapping of one address to another address. Typically this NAT is used for communication from private IP address to public IP address. The NAT Table has the following pre-defined chains: PREROUTING, POSTROUTING and OUTPUT.

* Mangle Table

  The Mangle table is used to alter the IP header which consists the IP address of source and destination, IP versions, segment of user data. The in-built chains that are available in this table are PREROUTING, OUTPUT, FORWARD, INPUT and POSTROUTING.

* Raw Table
  
  The purpose of raw table is connection tracking of the packages.

* Security Table  

  This  table  is  used for Mandatory Access Control (MAC) networking rules. Mandatory Access Control is implemented by Linux Security Modules such as SELinux.


24. What is prot, opt, in, out, source & destination?

* `prot` : It denotes the protocol, for instance, tcp, udp.

* `opt`: Special options for that specific rule.

* `in`: Name of input interface via which the packet is received

* `out`: Name of output interface via which the packet will be send

* `source`: Source IP address or Domain Name

* `destination`: Destination IP address or Domain Name

25. Why rules are added to the top?

When rules are added to the top it means a network packet will be checked against the rules serially. Now depending on the action(if it is a terminating action), if the packet matches the matching statement, the following rules are not checked and the action is executed. Otherwise the packet is checked with the following rules in the chain.

26. What type of rules we can add to the iptables?

* `ACCEPT`: It accpets the the network packets.

* `DROP`: It rejects the the network packets.

* `REJECT`: It rejects the the network packets and sends message to the sender.

27. Can we block a website by its domain name only?

Yes we can.

28. How can we persist rules in iptables?

Persisting rules in iptables mean to store the rules in `/etc/iptables/rules.v4` or `/etc/iptables/rules.v6` such that they do not get deleted on reboot. The iptables-persistent package should be pre installed.

To persist the rule we need to follow the following commands:

```bash
sudo iptables-save > /etc/iptables/rules.v4
sudo reboot
```

29. How can we save rules in iptables?

Persisting rules in iptables mean to store the rules in `/etc/iptables/rules.v4` or `/etc/iptables/rules.v6` such that they do not get deleted on reboot. The iptables-persistent package should be pre installed.

To persist the rule we need to follow the following commands:

```bash
sudo iptables-save > /etc/iptables/rules.v4
sudo reboot
```

30. What is the difference between ufw & iptables.

| iptables | ufw |
| -------- | ------- |
| iptables is a CLI tool that allows admins to configure specific rules that will enforce Linux kernel to perform actions such as accept, drop, reject, modify network packets. | UFW - Uncomplicated Firewall. It is also a firewall configuration tool implemented on top of iptables and developed to ease iptables firewall configuration. |
| To use IPtables you need to understand TCP/IP connections, more complicated protocols and it can still be complicated. | UFW provides a basic default firewall and allows you to easily turn on and off basic services. It provides a user friendly way to create an IPv4 or IPv6 host-based firewall. UFW is not as flexible but is easier to configure for common scenarios. |

31. What are public & private keys?

When we use ssh-keygen command a public and private key is generated.

* A public key that is copied to the SSH server. Once an SSH server receives a public key from a user and considers the key trustworthy, the server marks the key as authorized in its authorized_keys file. Such keys are called authorized keys. Now the user with private key for this corresponding public key can connect to the server.

* A private key that remains only with the user. The possession of this key is proof of the user's identity. Only a user in possession of a private key that corresponds to the public key at the server will be able to authenticate successfully. The private keys need to be stored and handled carefully, and no copies of the private key should be distributed. The private keys used for user authentication are called identity keys.

32. How does ssh work?


The SSH protocol is based on the client-server model. Therefore, an SSH client must initiate an SSH session with an SSH server. The steps involved in creating an SSH session go like this:

* Client contacts server to initiate a connection.
* The server responds by sending the client a public cryptography key.
* The server negotiates parameters and opens a secure channel for the client.
* The user, through their client, logs into the server.

33. What is the difference between HTTP & HTTPS.

HTTPS is HTTP with encryption. The only difference between the two protocols is that HTTPS uses TLS (SSL) to encrypt normal HTTP requests and responses. As a result, HTTPS is far more secure than HTTP. A website that uses HTTP has `http://` in its URL, while a website that uses HTTPS has `https://`.

34. What is SSL?

SSL certificates are what enable websites to move from HTTP to HTTPS, which is more secure. An SSL certificate is a data file hosted in a website's origin server. SSL certificates make SSL/TLS encryption possible, and they contain the website's public key and the website's identity, along with related information. Devices attempting to communicate with the origin server will reference this file to obtain the public key and verify the server's identity. The private key is kept secret and secure.

35. What is the difference between apt update & apt upgrade.

| apt update | apt upgrade |
| - | - |
| `apt update` is used to update the apt cache with the updated list of packages and its dependencies | `apt upgrade` is used to upgrade all the applications installed using apt package manager. |

36. What do repositories contain in a Linux system?

Repositories in Linux is a storage location which consists large number of packages. For Ubuntu there are four main repositories:
* Main
* Universe
* Restricted
* Multiverse

37. What are the package managers used in Linux?

Package managers are tools which automate the process of installing, upgrading and removing application along with dependancies.

38. What does the number represent after the file permissions?

It dentoes the number of folders in the directory.

39. What is the difference between apt and apt-get?

apt consists some of the most widely used features from apt-get and apt-cache leaving aside seldom used features.
So with apt, we get all the necessary tools in one place. The main aim of apt is to provide an efficient way of handling package. It has fewer but sufficient command options but in a more organized way. On top of that, it enables a few options by default that is actually helpful for the end users.

40. How can I give access to someone to my AWS instance?

We can achieve this by adding the public key of the user to the aws instance authorized_key.

41. What are daemon applications?

Daemon applications refer to background applications.

42. What does a ".d" represent after a filename?

"d" stands for directory and such a directory is a collection of configuration files which are often fragments that are included in the main configuration file. The point is to compartmentalize configuration concerns to increase maintainability.

43. What happens when a pem file gets deleted?

We cannot the acces the aws instance if the pem is deleted.

44. What information is stored in the /etc/hosts file?

It stores ip address for hostnames and is used to translate hostnames to its corresponding ip address.

45. What is SCP & what does this command do?

The SCP command or **secure copy allows secure transferring of files in between the local host and the remote host** or between two remote hosts. 

```bash
scp  /path/file_name ubuntu@ip destination
```

46. How port forwarding works?

**Port forwarding** is a technique that is used to allow external devices access to computers services on private networks. Local port forwarding is the most common type of port forwarding. It is used to let a user connect from the local computer to another server, i.e. forward data securely from another client application running on the same computer as a [Secure Shell](https://en.wikipedia.org/wiki/Secure_Shell) (SSH) client

47. How can we connect without IP to AWS instance?

We set `Host` , `User`, `IdentityFile` and `Hostname` in the `.ssh/config` file. The syntax is
```
Host server1
HostName 18.118.157.232
User ubuntu
IdentityFile ~/Downloads/demo-pair.pem

```

48. What is an ssh agent?

ssh-agent is a key manager for SSH. It holds your keys and certificates in memory, unencrypted, and ready for use by ssh. It saves you from typing a passphrase every time you connect to a server. It runs in the background on your system, separately from ssh, and it usually starts up the first time you run ssh after a reboot.

49. Create a unit file for any application.

[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target
Conflicts=apache2.service

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target

50. What is RHEL?

RHEL stands for Red Hat Enterprise Linux. It is commercial Linux distribution developed by Red hat. It is licensed and hence not free.
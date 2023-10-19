Republic of Ireland
Munster Technological University
Department of Computer Science
Student: Jose Lo Huang

Python Script net_attack.py
Creation Date: 29/11/2021
Updates:
01/12/2021 - Add functions read_ip_list, is_reachable and scan_port
02/12/2021 - Add functions bruteforce_telnet
03/12/2021 - Add functions bruteforce_ssh and bruteforce_web
04/12/2021 - Modify the code to accept -d flag
06/12/2021 - Modify the code to accept -L and -P flags
07/12/2021 - Tests, edge cases and add comments and documentation
 
This code scans hosts and ports from a list of IPs provided to check 
if they are available and attempt brute force to login to those systems, 
and optionally send files.

1. Mode Multicast (-t & -d)

In this mode the script will scan ports specified by the user on a list 
of hosts provided on a file. If the user provided 22, 23, 80, 8080 or 8888 
as ports; it will try to brute-force login according to the protocol (SSH, 
Telnet or Web). Optionally, it will transfer a file to the hosts where SSH 
or Telnet are active.

2. Mode Broadcast (-L & -P)

In this mode the script will scan ports specified by the user on all the 
/24 networks for each available network interface on the attacker host. If 
the user provided 22, 23, 80, 8080 or 8888 as ports; it will try to 
brute-force login according to the protocol (SSH, Telnet or Web). 
Optionally, it will transfer a file to the hosts where SSH or Telnet are 
active.

==========================================================================

Usage: 

sudo ./net_attack.py {-t <file_name>|-L} -p <port_list> -u <user> -f <pwd_file> [{-d <file_to_transfer.txt>|-P}]

-t <file_name>: The file with the IP list.
-L : Scan all the local /24 network.
-p <port_list>: The list of ports to scan.
-u <user>: The user to attack.
-f <pwd_file>: The file with sample passwords.
-d <file_to_transfer.txt>: The optional file to transfer to the target hosts.
-P : Optional if you want to propagate the script bundle on the local /24 network.

Example 1: ./net_attack.py -t ip_list.txt -p 22,23,80 -u admin -f pwd_list.txt 
Example 2: ./net_attack.py -L -p 22,80 -u admin -f pwd_list.txt -P 
Example 3: ./net_attack.py -t ip_list.txt -p 22,80 -u admin -f pwd_list.txt -d file.txt
 
=========================================================================



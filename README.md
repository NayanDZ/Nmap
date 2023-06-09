# Nmap

## 1. Passive Reconnaissance
In passive reconnaissance, you depend on publicly available information that you can access from publicly available resources without directly engaging with the target. like you are looking at target domain from afar without stepping foot on that domain.
- Looking up DNS records of a domain from a public DNS server.
- Checking job ads related to the target website.
- Reading news articles about the target company.
- WHOIS protocol to get various information about the domain name we were looking up

 * **WHOIS:** is a request and response protocol that follows the RFC 3912 specification.
  
	A WHOIS server listens on TCP port 43 for incoming requests. 
	The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing.
	The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:
	
	> *Registrar: Via which registrar was the domain name registered?*
	
	> *Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service) Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?*
	
	> *Name Server: Which server to ask to resolve the domain name?*

	``` 
	$: whois tryhackme.com 
	```
* **nslookup (Name Server Look Up):** Find the IP address of a domain name using nslookup.

	```
	$: nslookup tryhackme.com   ||OR||    $: nslookup A tryhackme.com  1.1.1.1
	
	###	
	OPTIONS		Result
	A		IPv4 Addresses
	AAAA		IPv6 Addresses
	CNAME		Canonical Name
	MX		Mail Servers
	SOA		Start of Authority
	TXT		TXT Records
	
	## You can choose any local or public DNS server to query. 
	Cloudflare offers: 1.1.1.1 and 1.0.0.1, 
	Google offers: 8.8.8.8 and 8.8.4.4
	```
* **dig (Domain Information Groper):** For more advanced DNS queries and additional functionality

	```
	$: dig tryhackme.com MX  ||OR|| $: dig @1.1.1.1 tryhackme.com MX
	```


> DNS lookup tools, such as nslookup and dig, cannot find subdomains on their own. The domain you are inspecting might include a different subdomain that can reveal much information about the target

 ``` 
 DNSDumpster and Shodan.io 
 
 ## Using Shodan.io we can learn several things related to our search, such as: IP address, hosting company, geographic location, server type and version
 ```


## 2. Active Reconnaissance
Active reconnaissance requires direct engagement with the target. Connecting to one of the target servers such as HTTP, FTP, and SMTP using simple tools to gather information about the network, system, and services.

- **Ping:** is used to check network connectivity or checking whether the remote system is online.
``` 
$: ping google.com  ||	  $: ping -c 10 google.com || 	$: ping -n google.com
```
	
- **Traceroute:** The purpose of a traceroute is to find the IP addresses of the routers or hops that a packet traverses as it goes from your system to a target host.
```
$: traceroute google.com
```

- **Telnet:** telnet uses the TELNET protocol for remote administration. The default port used by telnet is 23. From a security perspective, telnet sends all the data, including usernames and passwords, in cleartext. Sending in cleartext makes it easy for anyone, who has access to the communication channel, to steal the login credentials. The secure alternative is SSH (Secure SHell) 22 port protocol.

```
$: telnet MACHINE_IP 80 	|| 	$: telnet google.com 
```

- **nc (Netcat):** Netcat supports both TCP and UDP protocols. It can function as a client that connects to a listening port; alternatively, it can act as a server that listens on a port of your choice. Hence, it is a convenient tool that you can use as a simple client or server over TCP or UDP.

```
## to collect its banner using nc:
$: nc google.com 80
GET / HTTP/1.1
host: netcat

## You can use netcat to listen on a TCP port and connect to a listening port on another system.

On the server system, where you want to open a port and listen on it, you can issue nc -lp 1234 or better yet, nc -vnlp 1234
netcat as client	nc MACHINE_IP PORT_NUMBER
netcat as server	nc -lvnp PORT_NUMBER   || nc -lp PORT_NUMBER

## Refrence: https://tryhackme.com/room/activerecon
```


## 3. Nmap Live Host Discovery
Discovering Live Hosts using:

1. ARP from Link Layer
2. ICMP from Network Layer
3. TCP from Transport Layer
4. UDP from Transport Layer

There are various ways to discover online hosts. When no host discovery options are provided, Nmap follows the following approaches to discover live hosts:

1. When a privileged user tries to ***scan targets on a local network (Ethernet), Nmap uses ARP requests.*** A privileged user is root or a user who belongs to sudoers and can run sudo.
2. When a privileged user tries to ***scan targets outside the local network, Nmap uses ICMP echo requests, TCP ACK (Acknowledge) to port 80, TCP SYN (Synchronize) to port 443, and ICMP timestamp request.***
3. When an unprivileged user tries to ***scan targets outside the local network, Nmap resorts to a TCP 3-way handshake by sending SYN packets to ports 80 and 443.***

> Discover online hosts without port-scanning you can use: ``` $: nmap -sn TARGETS ```

**1. Host Discovery Using ARP**

ARP scan is possible only if you are on the same subnet as the target systems. 

If you want all the live systems on the same subnet as our target machine to perform an ARP scan without port-scanning, you can use: 
```
$: sudo nmap -PR -sn MACHINE_IP/24, where -PR indicates ARP scan

## Nmap sends ARP requests to all the target computers, and those online should send an ARP reply back.
```
One popular choice is ```$: arp-scan --localnet``` or simply ```$: arp-scan -l```. This command will send ARP queries to all valid IP addresses on your local networks. 

If your system has more than one interface and you are interested in discovering the live hosts on one of them, you can specify the interface using -I. For instance, ``` $: sudo arp-scan -I eth0 -l``` will send ARP queries for all valid IP addresses on the eth0 interface.


**2 Host Discovery Using ICMP**

To use ICMP echo request to discover live hosts, add the option **-PE** : ``` sudo nmap -PE -sn MACHINE_IP/24  //where -sn don’t want to port scan ```

ICMP echo scan works by sending an ICMP echo request and expects the target to reply with an ICMP echo reply if it is online.

Different subnet: Because ICMP echo requests tend to be blocked, you might also consider ICMP Timestamp or ICMP Address Mask requests to tell if a system is online. 
Nmap uses timestamp request (ICMP Type 13) and checks whether it will get a Timestamp reply (ICMP Type 14). 
```
## ICMP timestamp requests use -PP option: 
$: nmap -PP -sn MACHINE_IP/24

## ICMP Address Mask requests can be enabled with the option -PM
nmap -PM -sn MACHINE_IP/24
```

**3 Host Discovery Using TCP and UDP**

- ***TCP SYN Ping:*** TCP SYN Ping send a packet with the SYN(Synchronize) flag set [TCP 3-way handshake usually works](https://tryhackme.com/room/nmap01) you can perform via the option **-PS**: 
``` 
$: sudo nmap -PS22,80,443 -sn MACHINE_IP/30 
```
> Unprivileged users have no choice but to complete the 3-way handshake if the port is open.

Privileged users(root & sudoers) can send TCP SYN packets and don’t need to complete the TCP 3-way handshake even if the port is open: 
``` 
$: nmap -PS -sn MACHINE_IP/24 
```

- ***TCP ACK Ping:*** We can use response to detect if the target host is up.

Any TCP packet with an ACK flag should get a TCP packet back with an RST flag set. The target responds with the RST flag set because the TCP packet with the ACK flag is not part of any ongoing connection. 
```
sudo nmap -PA22,80,443 -sn MACHINE_IP/30
```

- ***UDP Ping:*** We can use UDP to discover if the host is online.

Sending a UDP packet to an open port is not expected to lead to any reply. However, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet; this indicates that the target system is up and available.

```
sudo nmap -PU53,161,162 -sn MACHINE_IP/30
```

## 4. Nmap Basic Port Scaning
- **TCP Connect Scan:** TCP connect scan works by completing the TCP 3-way handshake. In standard TCP connection establishment, the client sends a TCP packet with SYN flag set, and the server responds with SYN/ACK if the port is open; finally, the client completes the 3-way handshake by sending an ACK.

We are interested in learning whether the TCP port is open, not establishing a TCP connection. Hence the connection is torn as soon as its state is confirmed by sending a RST/ACK. You can choose to run TCP connect scan using -sT option.
```
$: nmap -sT MACHINE_IP
```

- **TCP SYN Scan:** Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan, and it requires a privileged (root or sudoer) user to run it. SYN scan does not need to complete the TCP 3-way handshake; instead, it tears down the connection once it receives a response from the server. Because we didn’t establish a TCP connection, this decreases the chances of the scan being logged. We can select this scan type by using the -sS option.
```
$: nmap -sS MACHINE_IP
```

- **UDP Scan:** UDP is a connectionless protocol, and hence it does not require any handshake for connection establishment. We cannot guarantee that a service listening on a UDP port would respond to our packets. However, if a UDP packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned. You can select UDP scan using the -sU options.
```
$: sudo nmap -sU MACHINE_IP
```

##  🧙‍♂️ Nmap Command options
1. How do I scan specific ports?
```
## Scan port 80
nmap -p 80 192.168.1.1

## Scan TCP port 80
nmap -p T:80 192.168.1.1

## Scan UDP port 53
nmap -p U:53 192.168.1.1

port list: -p22,80,443 will scan ports 22, 80 and 443.

port range: -p1-1023 will scan all ports between 1 and 1023 inclusive, 
	    -p20-25 will scan ports between 20 and 25 inclusive.
            -p- which will scan all 65535 ports. 
	    -F if you want to scan the most common 100 ports.(fast scan?)
	    --top-ports 10 will check the ten most common ports.

You can control the scan timing using -T<0-5>
				      -T0 is the slowest (paranoid), 
				      -T5 is fastest way to scan. According to Nmap manual page, there are six templates:

					paranoid (0)
					sneaky (1)
					polite (2)
					normal (3)
					aggressive (4)
					insane (5)

--min-rate <number> and --max-rate <number> 
--max-rate=10 ensures that your scanner is not sending more than ten packets per second.

--min-parallelism <numprobes> and --max-parallelism <numprobes>  probing parallelization specifies the number of such probes that can be run in parallel. For instance, --min-parallelism=512 pushes Nmap to maintain at least 512 probes in parallel; these 512 probes are related to host discovery and open ports.
```

2. Scan a single host or an IP address (IPv4)
```
### Scan a single ip address ###
nmap 192.168.1.1
	
## Scan a host name ###
nmap server1.server
	
## Scan a host name with more info###
nmap -v server.server
```
	
3. Scan multiple IP address or subnet (IPv4)
```
nmap 192.168.1.1 192.168.1.2 192.168.1.3
	
## works with same subnet i.e. 192.168.1.0/24
nmap 192.168.1.1,2,3
	
You can scan a range of IP address too:
nmap 192.168.1.1-20
	
You can scan a range of IP address using a wildcard:
nmap 192.168.1.*
	
Finally, you scan an entire subnet:
nmap 192.168.1.0/24
```
4. Read list of hosts/networks from a file (IPv4)
```
nmap -iL /tmp/test.txt
```

5. Turn on OS and version detection scanning script (IPv4)
```
nmap -A 192.168.1.254
nmap -v -A 192.168.1.1

# Detect remote operating system
nmap -O 192.168.1.1
nmap -O --osscan-guess 192.168.1.1
nmap -v -O --osscan-guess 192.168.1.1
```
6. Find out if a host/network is protected by a firewall
```
nmap -sA 192.168.1.254
```
7. Scan a host when protected by the firewall
```
nmap -PN 192.168.1.1
```
8. Scan an IPv6 host/address
```
nmap -6 IPv6-Address-Here
nmap -6 server1.server
nmap -6 2607:f0d0:1002:51::4
nmap -v A -6 2607:f0d0:1002:51::4
```
9. Scan a network and find out which servers and devices are up and running
```
nmap -sP 192.168.1.0/24
```

10. Display the reason a port is in a particular state
```
nmap --reason 192.168.1.1
```
11. Only show open (or possibly open) ports
```
nmap --open 192.168.1.1
```
12. Show all packets sent and received
```
nmap --packet-trace 192.168.1.1
```

13. Show host interfaces and routes
```
nmap --iflist
```

14. How do I detect remote services (server / daemon) version numbers?
```
nmap -sV 192.168.1.1	
```

15. Scan a host using TCP ACK (PA) and TCP Syn (PS) ping
```
nmap -PS 192.168.1.1
nmap -PS 80,21,443 192.168.1.1
nmap -PA 192.168.1.1
nmap -PA 80,21,200-512 192.168.1.1
```
	
16. Scan a host using IP protocol ping.
```
nmap -PO 192.168.1.1	
```
	
17. Find out the most commonly used TCP ports using TCP SYN Scan
```
### Stealthy scan ###
nmap -sS 192.168.1.1
	
### Find out the most commonly used TCP ports using TCP connect scan (warning: no stealth
scan)
### OS Fingerprinting ###
nmap -sT 192.168.1.1
	
### Find out the most commonly used TCP ports using TCP ACK scan
nmap -sA 192.168.1.1
	
### Find out the most commonly used TCP ports using TCP Window scan
nmap -sW 192.168.1.1
	
### Find out the most commonly used TCP ports using TCP Maimon scan
nmap -sM 192.168.1.1	
```

18. Scan a firewall for security weakness
```
## TCP Null Scan to fool a firewall to generate a response ##
## Does not set any bits (TCP flag header is 0) ##
nmap -sN 192.168.1.254
	
## TCP Fin scan to check firewall ##
## Sets just the TCP FIN bit ##
nmap -sF 192.168.1.254
	
## TCP Xmas scan to check firewall ##
## Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree ##
nmap -sX 192.168.1.254
```
	
19. Scan a firewall for packets fragments
```
# The -f option causes the requested scan (including ping scans) to use tiny fragmented IP packets. 
The idea is to split up the TCP header over several packets to make it harder for packet filters, 
intrusion detection systems, and other annoyances to detect what you are doing.
nmap -f 192.168.1.1
nmap -f fw2.nixcraft.net.in
nmap -f 15 fw2.nixcraft.net.in
	
## Set your own offset size with the --mtu option ##
nmap --mtu 32 192.168.1.1
```
	
20. Cloak a scan with decoys
```
# The -D option it appear to the remote host that the host(s) you specify as decoys are scanning the target network too.
Thus their IDS might report 5-10 port scans from unique IP addresses, but they won't know which IP was scanning them and which were innocent decoys:
nmap -n -Ddecoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip
nmap -n -D192.168.1.5,10.5.1.2,172.1.2.4,3.4.2.1 192.168.1.5
```
	
21. Scan a firewall for MAC address spoofing
```
### Spoof your MAC address ##
nmap --spoof-mac MAC-ADDRESS-HERE 192.168.1.1
	
### Add other options ###
nmap -v -sT -PN --spoof-mac MAC-ADDRESS-HERE 192.168.1.1

### Use a random MAC address ###
### The number 0, means nmap chooses a completely random MAC address ###
nmap -v -sT -PN --spoof-mac 0 192.168.1.1
```
	
22. Save output to a text file.
```
nmap 192.168.1.1 > output.txt
nmap -oN /path/to/filename 192.168.1.1
nmap -oN output.txt 192.168.1.1	
```

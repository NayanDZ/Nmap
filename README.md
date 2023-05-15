# Nmap

## 1. Passive Reconnaissance
In passive reconnaissance, you rely on publicly available knowledge. It is the knowledge that you can access from publicly available resources without directly engaging with the target. Think of it like you are looking at target territory from afar without stepping foot on that territory.

- Looking up DNS records of a domain from a public DNS server.
- Checking job ads related to the target website.
- Reading news articles about the target company.
(WHOIS)WHOIS protocol to get various information about the domain name we were looking up
WHOIS is a request and response protocol that follows the RFC 3912 specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:

Registrar: Via which registrar was the domain name registered?
Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
Name Server: Which server to ask to resolve the domain name?

EX: whois tryhackme.com


Find the IP address of a domain name using nslookup, which stands for Name Server Look Up

nslookup DOMAIN_NAME     ||OR||    nslookup OPTIONS DOMAIN_NAME SERVE
nslookup tryhackme.com   ||OR||    nslookup A tryhackme.com  1.1.1.1

OPTIONS	Result
A		IPv4 Addresses
AAAA	IPv6 Addresses
CNAME	Canonical Name
MX		Mail Servers
SOA		Start of Authority
TXT		TXT Records


You can choose any local or public DNS server to query. 
Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4


For more advanced DNS queries and additional functionality, you can use dig, the acronym for “Domain Information Groper,

EX: dig DOMAIN_NAME   ||OR|| dig @SERVER DOMAIN_NAME TYPE

dig tryhackme.com MX  ||OR|| dig @1.1.1.1 tryhackme.com MX


DNS lookup tools, such as nslookup and dig, cannot find subdomains on their own. The domain you are inspecting might include a different subdomain that can reveal much information about the target

 DNSDumpster and Shodan.io
 
When you are tasked to run a penetration test against specific targets, as part of the passive reconnaissance phase, a service like Shodan.io can be helpful to learn various pieces of information about the client’s network, without actively connecting to it.

 Via this Shodan.io search result, we can learn several things related to our search, such as:

IP address
hosting company
geographic location
server type and version


## 2. Active Reconnaissance
Active reconnaissance, on the other hand, cannot be achieved so discreetly. It requires direct engagement with the target. Think of it like you check the locks on the doors and windows, among other potential entry points.

Connecting to one of the company servers such as HTTP, FTP, and SMTP.
Calling the company in an attempt to get information (social engineering).
Entering company premises pretending to be a repairman.


we discuss using simple tools to gather information about the network, system, and services

- Ping: This was used to check network connectivity /  checking whether the remote system is online 
	ping google.com || ping -c 10 google.com || ping -n google.com 
- Traceroute: The purpose of a traceroute is to find the IP addresses of the routers or hops that a packet traverses as it goes from your system to a target host 
	traceroute google.com
- Telnet: telnet uses the TELNET protocol for remote administration. The default port used by telnet is 23. From a security perspective, telnet sends all the data, including usernames and passwords, in cleartext. Sending in cleartext makes it easy for anyone, who has access to the communication channel, to steal the login credentials. The secure alternative is SSH (Secure SHell) protocol

telnet MACHINE_IP 80 || telnet google.com 

- nc: Netcat supports both TCP and UDP protocols. It can function as a client that connects to a listening port; alternatively, it can act as a server that listens on a port of your choice. Hence, it is a convenient tool that you can use as a simple client or server over TCP or UDP.

First, you can connect to a server, as you did with Telnet, to collect its banner using nc MACHINE_IP PORT, which is quite similar to our previous telnet MACHINE_IP PORT. Note that you might need to press SHIFT+ENTER after the GET line.

In the terminal shown above, we used netcat to connect to MACHINE_IP port 80 using nc MACHINE_IP 80. Next, we issued a get for the default page using GET / HTTP/1.1; we are specifying to the target server that our client supports HTTP version 1.1. Finally, we need to give a name to our host, so we added on a new line, host: netcat; you can name your host anything as this has no impact on this exercise.

On the server system, where you want to open a port and listen on it, you can issue nc -lp 1234 or better yet, nc -vnlp 1234

netcat as client	nc MACHINE_IP PORT_NUMBER
netcat as server	nc -lvnp PORT_NUMBER

https://tryhackme.com/room/activerecon

## 3. Nmap Live Host Discovery

Discovering Live Hosts:
	- ARP from Link Layer
	- ICMP from Network Layer
	- TCP from Transport Layer
	- UDP from Transport Layer

**1 Nmap Host Discovery Using ARP**
There are various ways to discover online hosts. When no host discovery options are provided, Nmap follows the following approaches to discover live hosts:

1. When a privileged user tries to scan targets on a local network (Ethernet), Nmap uses ARP requests. A privileged user is root or a user who belongs to sudoers and can run sudo.
2. When a privileged user tries to scan targets outside the local network, Nmap uses ICMP echo requests, TCP ACK (Acknowledge) to port 80, TCP SYN (Synchronize) to port 443, and ICMP timestamp request.
3. When an unprivileged user tries to scan targets outside the local network, Nmap resorts to a TCP 3-way handshake by sending SYN packets to ports 80 and 443.

If you want to use Nmap to discover online hosts without port-scanning the live systems, you can issue: nmap -sn TARGETS

ARP scan is possible only if you are on the same subnet as the target systems. 
If you want all the live systems on the same subnet as our target machine to perform an ARP scan without port-scanning, you can use: sudo nmap -PR -sn MACHINE_IP/24, where -PR indicates ARP scan

ARP scan works, as shown in the figure below. Nmap sends ARP requests to all the target computers, and those online should send an ARP reply back.

One popular choice is arp-scan --localnet or simply arp-scan -l. This command will send ARP queries to all valid IP addresses on your local networks. Moreover, if your system has more than one interface and you are interested in discovering the live hosts on one of them, you can specify the interface using -I. For instance, sudo arp-scan -I eth0 -l will send ARP queries for all valid IP addresses on the eth0 interface.


**2 Nmap Host Discovery Using ICMP**
To use ICMP echo request to discover live hosts, add the option -PE : sudo nmap -PE -sn MACHINE_IP/24  where -sn don’t want to port scan

ICMP echo scan works by sending an ICMP echo request and expects the target to reply with an ICMP echo reply if it is online.

different subnet
Because ICMP echo requests tend to be blocked, you might also consider ICMP Timestamp or ICMP Address Mask requests to tell if a system is online. Nmap uses timestamp request (ICMP Type 13) and checks whether it will get a Timestamp reply (ICMP Type 14). 

Adding the -PP option tells Nmap to use ICMP timestamp requests: 
nmap -PP -sn MACHINE_IP/24

ICMP Address Mask requests can be enabled with the option -PM
nmap -PM -sn MACHINE_IP/24

**3 Nmap Host Discovery Using TCP and UDP**
TCP SYN Ping (We can send a packet with the SYN (Synchronize) flag set)
TCP 3-way handshake usually works https://tryhackme.com/room/nmap01


If you want Nmap to use TCP SYN ping, you can do so via the option -PS : sudo nmap -PS22,80,443 -sn MACHINE_IP/30

Privileged users (root and sudoers) can send TCP SYN packets and don’t need to complete the TCP 3-way handshake even if the port is open, as shown in the figure below. Unprivileged users have no choice but to complete the 3-way handshake if the port is open. https://tryhackme.com/room/nmap01

nmap -PS -sn MACHINE_IP/24

TCP ACK Ping

The following figure shows that any TCP packet with an ACK flag should get a TCP packet back with an RST flag set. The target responds with the RST flag set because the TCP packet with the ACK flag is not part of any ongoing connection. The expected response is used to detect if the target host is up.

sudo nmap -PA22,80,443 -sn MACHINE_IP/30


UDP Ping
Finally, we can use UDP to discover if the host is online. Contrary to TCP SYN ping, sending a UDP packet to an open port is not expected to lead to any reply. However, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet; this indicates that the target system is up and available.

In the following figure, we see a UDP packet sent to an open UDP port and not triggering any response. However, sending a UDP packet to any closed UDP port can trigger a response indirectly indicating that the target is online.

sudo nmap -PU53,161,162 -sn MACHINE_IP/30


## 4. Nmap Basic Port Scans
TCP Connect Scan: TCP connect scan works by completing the TCP 3-way handshake. In standard TCP connection establishment, the client sends a TCP packet with SYN flag set, and the server responds with SYN/ACK if the port is open; finally, the client completes the 3-way handshake by sending an ACK.

We are interested in learning whether the TCP port is open, not establishing a TCP connection. Hence the connection is torn as soon as its state is confirmed by sending a RST/ACK. You can choose to run TCP connect scan using -sT.

nmap -sT MACHINE_IP

TCP SYN Scan: Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan, and it requires a privileged (root or sudoer) user to run it. SYN scan does not need to complete the TCP 3-way handshake; instead, it tears down the connection once it receives a response from the server. Because we didn’t establish a TCP connection, this decreases the chances of the scan being logged. We can select this scan type by using the -sS option

nmap -sS MACHINE_IP

UDP Scan: UDP is a connectionless protocol, and hence it does not require any handshake for connection establishment. We cannot guarantee that a service listening on a UDP port would respond to our packets. However, if a UDP packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned. You can select UDP scan using the -sU

sudo nmap -sU MACHINE_IP

port list: -p22,80,443 will scan ports 22, 80 and 443.
port range: -p1-1023 will scan all ports between 1 and 1023 inclusive, 
	      while -p20-25 will scan ports between 20 and 25 inclusive.
               -p- which will scan all 65535 ports. 
	     f you want to scan the most common 100 ports, add -F. Using --top-ports 10 will check the ten most common ports.

You can control the scan timing using -T<0-5>. 
-T0 is the slowest (paranoid), 
-T5 is the fastest. According to Nmap manual page, there are six templates:

paranoid (0)
sneaky (1)
polite (2)
normal (3)
aggressive (4)
insane (5)

--min-rate <number> and --max-rate <number> 
--max-rate=10 ensures that your scanner is not sending more than ten packets per second.

--min-parallelism <numprobes> and --max-parallelism <numprobes>  probing parallelization specifies the number of such probes that can be run in parallel. For instance, --min-parallelism=512 pushes Nmap to maintain at least 512 probes in parallel; these 512 probes are related to host discovery and open ports.

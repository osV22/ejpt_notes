# eJPT Notes - eLearnSecurity Junior Penetration Tester Certificate Notes

## Web & Cookies
- Using console and cannot use BurpSuite:
  - EX: `openssl s_client -connect targetSite.com:443`
  - flag `-quiet` to stop it from using verbose mode
  - Once connected we can do OPTIONS to see what's allowed, PUT can allow us to put a shell on the target

- Standard Cookies (local/ client-side)
  - If cookie domain is not specified it will be restrcited to just the immediate server and will not pass to other sub.domains.com.
  - Adding `http.only` flag when setting up a cookie pervents against XSS and other attacks that might allow reading of that cookie.
  - Adding `secure` flag in a cookie will only send cookies on HTTPS connections
  - When hijacking cookies, first make an init request to have the site generate us a cookie, **THEN** we can manipulate that and insert our own before submitting a GET request to the site with the weaponized cookie

- Session Cookies (server-side)
  - Slightly less secure to hide some of how the site functions, token-based
  - Can be submitted through GET links, EX: https://coolsite.com/index.php&sessid=kw3r9
  - PHP Sites use: `PHPSESSID`
  - JSP Sites use: `JSESSIONID`
  - **Web dev can set their own custom parameters though instead of the examples above for PHP & JSP.**
  - So biggest differecnes between HTTP and HTTPS are within the ssl/tls handshake
 
---
## Infomration Gathering
- Subdomain Enumeration
  - `cert.sh` - By far the best, a website that outputs TONS of subdomains based on certs domain checks
  - Go to a target site's cert details in the browser, it will show other subdomains as well if it's a shared cert
    - Careful from wildcard certs as they will return a subdomain for anything searched/ quiered. Ex: notrealsub.google.com will return valid if wildcard cert is on it.
  - Use Sublist3r or `dnsdumpster.com`
  - `VirusTotal.com` search for a domain 

- Ping Sweep: Used to create a map of a network
  - nmap is the defacto choice, as it allows you to input a list of ip ranges and much more
    - `nmap -sn 10.10.10.3-222`    
    - To force nmap os detection of a host even if it returns an error, try nmap -Pn -O TARGETIP (Note: This is very noisy)
    - More accurate OS scan: `nmap -sT -O TARGETIP/Range` (SYN-TCP based)
  - `fping -a -g IPRANGE`
    - `-a` flag, we want to see only hosts that are available (alive)
    - `-g` flag, we want this a ping sweep and not standard ping request
    - To hide offline hosts error messages use `2>/dev/null` at the end of the command ex: `fping -a -g 10.10.10.2 10.10.10.222 2>/dev/null` will show us only valid and alive hosts

- Port Scanning
  - `-sS` flag - Stealth scanning in nmap is decent against firewalls but can still be detected by some IDS. It's a SYN scan that drops the 3-handshake communication before connecting, which makes the service on the port unable of detecting it. 
  - `nmap <scan type> 10.10.10.3,6,9` will only scan hosts 10.10.10.3 then ...10.6 ... 10.9
  - DO NOT give up on `filtered` ports (request is blocked by FW/ IDS), try to force them with `-Pn`




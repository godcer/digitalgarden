---
{"dg-publish":true,"permalink":"/cyber-terms/","tags":["gardenEntry"],"noteIcon":""}
---

1. Web Crawler
2. Robot.txt
3. Sitemap
4. 



# subdomain app
- Subfinder. ☑️
- Amass ☑️
- Httpx☑️/Segfault
- Eyewitness screensorting  ☑️
- ffuf☑️
- shuffle dns☑️
- Dirsearch ☑️
### Screenshoting & dir bruteforce
- One for all (not able to install)
- Massdns
- Httpprobe.  ☑️
- Wfuzz -dirbrute☑️
- Ffuf -dirbrute
- Dirsearch-dirbrute
- Gobuster☑️
- Dig in kali for cname 
- Subzy (subdoamin takeover 404 error )
- Katana (js file etc)
- Subjs js files
- Getjs js extract 
- Secretfinder find jd etc secret 
- Mantra - api leak in js file
- Gitdocker - github recon 
- Gitgrabber - github recon 
- Trufflehog -git repo 
- Aws cli to access aws bucket
- Lazy s 3 for s 3 bucket  /repo awesome s 3 bucket
- S 3 scanner-preffered
- Grayhatwarefare
- 
### IP domain
- Mapcidr 
- Asnmap 
- Dnsx
- Naabu
- Massscan
- Rustscan
- Sandmap nmap on steroid
- Scan cannon 

### Xss  - Cross site scripting  [[Clippings/OWASP Top Ten  OWASP Foundation\|OWASP Top Ten  OWASP Foundation]] 
- To execute java script payload on web application with an intention to execute without proper validation from the  web application 
- Xss find at any   i) intention payload ii) modification payload
    - Search from 
    - Input form
    -  if no input form then on different parameter 
    -  
- Types of xss  based on popularity  
    - Reflected  
    -  stored
    - Dom
    - Blind 
- 





### NEW
- Massscan
- Androbugs
- Archivebox
- Assetfinder
- Bettercap
- Dnrecon
- Iam pesque
- Appleaks
- Harvester

Uprootjs burp extension
Keywords
- Parse 
- 🥠 cookies
- Content sniffing 
- Same origin policy
- Content security policy  /csp bypass 
  
  
### OSINT
- Maltego
- Harvester
- Shodan
- Recon-ng
- Spiderfoot
- Censys
- FOCA -document metadata
- Metagofil-document metadata etc
- OSRFramework
- Socil-engineering-toolkit
- 
### Github work around
- osintgraph
- instagram_analyzer
- 
  
  ## labs 
- Based on your earlier messages and the Docker setup from [hackingarticles.in](https://www.hackingarticles.in/web-application-pentest-lab-setup-using-docker/), here’s a list of the vulnerable labs you have installed (or intended to):

---

## ✅ Installed Vulnerable Labs (Docker Containers)

|Lab Name|Docker Image Name|Port|Description|
|---|---|---|---|
|**DVWA**|`vulnerables/web-dvwa`|8081|Classic vulnerable PHP/MySQL app|
|**Juice Shop**|`bkimminich/juice-shop`|8082|Modern app with full OWASP Top 10|
|**WebGoat**|`webgoat/webgoat`|8083|OWASP teaching app with lessons|
|**WebWolf**|`webgoat/webwolf`|8084|Companion to WebGoat (mail/capture)|
|**Mutillidae**|`citizenstig/nowasp`|8085|PHP app with many vulnerabilities|
|**bWAPP**|`raesene/bwapp`|8086|Buggy Web App (login + config-based vulns)|
|**SQLi-Labs**|`acgpiano/sqli-labs`|8087|Focused SQL Injection lab|

---

### 💡 Tip: To confirm which ones are currently installed (running or stopped), run:

```bash
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

It will show all containers, their status, and port bindings.

---

### 🧠 Optional Additions You Can Install

If you're interested in expanding:

|Lab Name|Image Name|Description|
|---|---|---|
|OWASP NodeGoat|`bkimminich/nodegoat`|OWASP Top 10 Node.js vulnerable app|
|Hackazon|`vulnerables/web-hackazon`|Dynamic e-commerce test app|
|DVNA|`appsecco/dvna`|Damn Vulnerable Node App|
|Altoro Mutual|`cturra/altoro-mutual`|Fake banking app (great for SSRF/IDOR)|

Let me know if you'd like a script to install any of these too.

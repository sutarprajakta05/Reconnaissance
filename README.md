# Reconnaissance
 Reconnaissance is important because it’s how you figure out an application’s attack surface. To look for bugs most efficiently, you need to discover all the possible ways of attacking a target before deciding on the most effective approach.
##### Manually Walking Through the Target
- First manually walk through the application to learn more about it
- Try to uncover every feature in the application that users can access by browsing through every page and clicking every link.
- Access the functionalities that you don’t usually use.
- This should give you a rough idea of what the attack surface

---
##### Google Dorking
- Advanced search-engine skills will help you find the resources you need quickly and accurately.
- Google searches are a powerful technique that hackers often use to perform recon. Hackers call this **Google dorking.**
- Google can be a means of discovering valuable information such as hidden admin portals, unlocked password files, and leaked authentication keys.
- ###### Google search :
	- site - 
		- Tells Google to show you results from a certain site only
		- This will help you quickly find the most reputable source on the topic that you are researching.
		- print site:python.org.
	- inurl -
		- Searches for pages with a URL that match the search string.
		- It’s a powerful way to search for vulnerable pages on a particular website
		- inurl:"/course/jumpto.php" site:example.com.
	- intitle - 
		- Finds specific strings in a page’s title.
		- This is useful because it allows you to find pages that contain a particular type of content.
		- intitle:"index of" site:example.com.
	- link - 
		- Searches for web pages that contain links to a specified URL
		- You can use this to find documentation about obscure technologies or vulnerabilities.
		- link:"https://en.wikipedia.org/wiki/ReDoS".
	- filetype - 
		- Searches for pages with a specific file extension
		- Hackers often use it to locate files on their target sites that might be sensitive, such as log and password files.
		- filetype:log site:example.com.
	- Wildcard (*) -
		- You can use the wildcard operator (*) within searches to mean any character or series of characters
		- "how to hack * using Google".
	- Quotes (" ") -
		- Adding quotation marks around your search terms forces an exact match.
		- this query will search for pages that contain the phrase how to hack: "how to hack".
		- this query will search for pages with the terms how, to, and hack, although not necessarily together
		- "how to hack"
	- Or (|) -
		- search for one search term or the other, or both at the same time.
		- "how to hack" site:(reddit.com | stackoverflow.com).
		- SQL Injection or SQLi: (SQL Injection | SQLi).
	- Minus (-) - 
		- The minus operator (-) excludes certain search results
		- how to hack websites but not php: **"how to hack websites" -php.**

	- look for all of a company’s subdomains:
		- site:*.example.com
	- look for special endpoints that can lead to vulnerabilities
		- site:example.com inurl:app/kibana
	- find company resources hosted by a third party online such as Amazon S3 buckets
		- site:s3.amazonaws.com COMPANY_NAME
	- Look for special extensions that could indicate a sensitive file (.php, cfm, asp, .jsp, and .pl,)
		- site:example.com ext:php 
		- site:example.com ext:log
	- combine search terms for a more accurate search
		- site:example.com ext:txt password
	
	- Google Hacking Database
		- website that hackers and security practitioners use to share Google search queries for finding security-related information.
		- (https://www.exploit-db.com/google-hacking-database/)
	
---
##### Scope Discovery 
###### WHOIS and Reverse WHOIS
- When companies or individuals register a domain name, they need to supply identifying information, such as their mailing address, phone number, and email address, to a domain registrar.
- Anyone can then query this information by using the whois command
-  `whois facebook.com`
- find the associated contact information, such as an email, name, address, or phone number
- Reverse WHOIS is extremely useful for finding obscure or internal domains not otherwise disclosed to the public.
- Use a public reverse WHOIS tool like ViewDNS.info (https://viewdns.info/reversewhois/) to conduct this search.

---
##### IP Addresses
- Discovering your target’s top-level domains is to locate IP addresses.
- Find the IP address of a domain you know by running the ==**nslookup**== command.
- You can see here that facebook.com is located at 157.240.2.35:
 ```bash
  $ nslookup facebook.com 
  Server: 192.168.0.1 
  Address: 192.168.0.1#53 
  Non-authoritative answer: 
  Name: facebook.com 
  Address: 157.240.2.35
  ```
- Once you’ve found the IP address of the known domain, perform a reverse IP lookup.
- Reverse IP searches look for domains hosted on the same server, given an IP or domain.
- You can also use ViewDNS.info for this.
- Run the ==whois== command on an IP address
1. Then see if the target has a dedicated IP range by checking the ==NetRange== field.
2. An IP range is a block of IP addresses that all belong to the same organization.
3. If the organization has a dedicated IP range, any IP you find in that range belongs to that organization:

```bash
$ whois 157.240.2.35

NetRange: 157.240.0.0 - 157.240.255.255 
CIDR: 157.240.0.0/16 
NetName: THEFA-3 
NetHandle: NET-157-240-0-0-1 
Parent: NET157 (NET-157-0-0-0-0) 
NetType: Direct Assignment 
OriginAS: Organization: Facebook, Inc. (THEFA-3) 
RegDate: 2015-05-14 
Updated: 2015-05-14 
Ref: https://rdap.arin.net/registry/ip/157.240.0.0 
OrgName: Facebook, Inc. 
OrgId: THEFA-3 Address: 1601 Willow Rd. 
City: Menlo Park 
StateProv: CA 
PostalCode: 94025 
Country: US 
RegDate: 2004-08-11 
Updated: 2012-04-17 
Ref: https://rdap.arin.net/registry/entity/THEFA-3 
OrgAbuseHandle: OPERA82-ARIN 
OrgAbuseName: Operations 
OrgAbusePhone: +1-650-543-4800 
OrgAbuseEmail: noc@fb.com 
OrgAbuseRef: https://rdap.arin.net/registry/entity/OPERA82-ARIN OrgTechHandle: OPERA82-ARIN 
OrgTechName: Operations 
OrgTechPhone: +1-650-543-4800 
OrgTechEmail: noc@fb.com 
OrgTechRef: https://rdap.arin.net/registry/entity/OPERA82-ARIN
```
- Another way of finding IP addresses in scope is by looking at autonomous systems, which are routable networks within the public internet
- ==Autonomous system numbers (ASNs)== identify the owners of these networks.
- By checking if two IP addresses share an ASN, you can determine whether the IPs belong to the same owner.
1. To figure out if a company owns a dedicated IP range, run several IP-to-ASN translations to see if the IP addresses map to a single ASN.
2. If many addresses within a range belong to the same ASN, the organization might have a dedicated IP range.
3. From the following output, we can deduce that any IP within the 157.240.2.21 to 157.240.2.34 range probably belongs to Facebook:
```bash
$ whois -h whois.cymru.com 157.240.2.20 AS | IP | AS Name 32934 | 157.240.2.20 | FACEBOOK, US 
$ whois -h whois.cymru.com 157.240.2.27 AS | IP | AS Name 32934 | 157.240.2.27 | FACEBOOK, US 
$ whois -h whois.cymru.com 157.240.2.35 AS | IP | AS Name 32934 | 157.240.2.35 | FACEBOOK, US
```
- The -h flag in the whois command sets the WHOIS server to retrieve information from
- whois.cymru.com is a database that translates IPs to ASNs.
- If the company has a dedicated IP range and doesn’t mark those addresses as out of scope, you could plan to attack every IP in that range.

---
##### Certificate Parsing
- finding hosts is to take advantage of the Secure Sockets Layer (SSL) certificates used to encrypt web traffic.
- An SSL certificate’s Subject Alternative Name field lets certificate owners specify additional hostnames that use the same certificate,
- so you can find those hostnames by parsing this field.
- Use online databases like ==crt.sh, Censys, and Cert Spotter== to find certificates for a domain.
1. For example, by running a certificate search using crt.sh for facebook.com,
2. we can find Facebook’s SSL certificate.
3. You’ll see that that many other domain names belonging to Facebook are listed:
```
X509v3 Subject Alternative Name: 
DNS:*.facebook.com 
DNS:*.facebook.net 
DNS:*.fbcdn.net 
DNS:*.fbsbx.com 
DNS:*.messenger.com 
DNS: facebook.com 
DNS: messenger.com 
DNS:*.m.facebook.com 
DNS:*.xx.fbcdn.net 
DNS:*.xy.fbcdn.net 
DNS:*.xz.fbcdn.net
```
- The crt.sh website also has a useful utility that lets you retrieve the information in JSON format, rather than HTML, for easier parsing
- Just add the URL parameter output=json to the request URL: https://crt.sh/?q=facebook.com&output=json.

---
##### Subdomain Enumeration
- The best way to enumerate subdomains is to use automation.
- Tools like Sublist3r, SubBrute, Amass, and Gobuster can enumerate subdomains automatically with a variety of wordlists and strategies.
	1. ==Sublist3r== works by querying search engines and online subdomain databases
	2. ==SubBrute== is a brute-forcing tool that guesses possible subdomains until it finds real ones.
	3. ==Amass== uses a combination of DNS zone transfers, certificate parsing, search engines, and subdomain databases to find subdomains
- To use many subdomain enumeration tools, you need to feed the program a wordlist of terms likely to appear in subdomains
- Daniel Miessler’s SecLists at https://github.com/danielmiessler/SecLists/ is a pretty extensive one.
- You can also use a wordlist generation tool like Commonspeak2 (https://github.com/ assetnote/commonspeak2/) to generate wordlists based on the most current internet data.
- Finally, you can combine several wordlists found online or that you generated yourself for the most comprehensive results
```
#Here’s a simple command to remove duplicate items from a set of two wordlists.
  
  sort -u wordlist1.txt wordlist2.txt
```
- ==Gobuster== is a tool for brute-forcing to discover subdomains, directories, and files on target web servers.
- Its DNS mode is used for subdomain bruteforcing.
- Its DNS mode is used for subdomain bruteforcing.

```
gobuster dns -d target_domain -w wordlist
```

- A good tool for automating this process is Altdns (https://github.com/infosec-au/altdns/)
- which discovers subdomains with names that are permutations of other subdomain names

- In addition, you can find more subdomains based on your knowledge about the company’s technology stack
- For example, if you’ve already learned that example.com uses Jenkins, you can check if jenkins.example.com is a valid subdomain

---
##### Service Enumeration
- enumerate the services hosted on the machines you’ve found
- Since services often run on default ports, a good way to find them is by port-scanning the machine with either active or passive scanning
###### Active scanning
- you directly engage with the server
- Active scanning tools send requests to connect to the target machine’s ports to look for open ones
- You can use tools like ==Nmap== or ==Masscan== for active scanning.
- For example, this simple Nmap command reveals the open ports on scanme .nmap.org:

```bash
$ nmap scanme.nmap.org 
Nmap scan report for scanme.nmap.org (45.33.32.156) 
Host is up (0.086s latency). 
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f 
Not shown: 993 
closed ports 
PORT STATE SERVICE 
22/tcp open ssh 
25/tcp filtered smtp 
80/tcp open http 
135/tcp filtered msrpc 
445/tcp filtered microsoft-ds 
9929/tcp open nping-echo 
31337/tcp open Elite 
Nmap done: 1 IP address (1 host up) scanned in 230.83 seconds
```
###### Passive scanning
- Passive scanning is stealthier and helps attackers avoid detection.
- To find services on a machine without actively scanning it, you can use ==**Shodan**==
- a search engine that lets the user find machines connected to the internet.
- With Shodan, you can discover the presence of webcams, web servers, or even power plants based on criteria such as hostnames or IP addresses.

For example, if you run a Shodan search on 
```
scanme.nmap.org’s IP address, 45.33.32.156
```
You can see that the search yields different data than our port scan, and provides additional information about the server.

![[Screenshot 2025-09-24 213135 1.png]]

- Alternatives to Shodan include ==Censys== and ==Project Sonar==

---
##### Directory Brute-Forcing
- Finding directories on servers is valuable.
- Because through them, you might discover hidden admin panels, configuration files, password files, outdated functionalities, database copies, and source code files.
- If you can’t find any immediate exploits, directory information often tells you about the structure and technology of an application
- For example, a pathname that includes *phpmyadmin* usually means that the application is built with PHP
- You can use ==**Dirsearch**== or ==Gobuster== for directory brute-forcing
1. These tools use wordlists to construct URLs
2. Then request these URLs from a web server
3. If the server responds with a *status code* in the **200** range, the directory or file exists
4. This means you can browse to the page and see what the application is hosting there.
5. **404** means that the directory or file doesn’t exist.
6. **403** means it exists but is protected

> Examine 403 pages carefully to see if you can bypass the protection to access the content.

- Here’s an example of running a Dirsearch command. The -u flag specifies the hostname, and the -e flag specifies the file extension to use when constructing URLs:
###### Dirsearch:
```bash
$ ./dirsearch.py -u scanme.nmap.org -e php 
Extensions: php | HTTP method: get | Threads: 10 | Wordlist size: 6023 
Error Log: /tools/dirsearch/logs/errors.log 
Target: scanme.nmap.org 
[12:31:11] Starting: 
[12:31:13] 403 - 290B - /.htusers 
[12:31:15] 301 - 316B - /.svn -> http://scanme.nmap.org/.svn/ [12:31:15] 403 - 287B - /.svn/ 
[12:31:15] 403 - 298B - /.svn/all-wcprops 
[12:31:15] 403 - 294B - /.svn/entries 
[12:31:15] 403 - 297B - /.svn/prop-base/ 
[12:31:15] 403 - 296B - /.svn/pristine/ 
[12:31:15] 403 - 291B - /.svn/tmp/ 
[12:31:15] 403 - 315B - /.svn/text-base/index.php.svn-base [12:31:15] 403 - 293B - /.svn/props/ 
[12:31:15] 403 - 297B - /.svn/text-base/ 
[12:31:40] 301 - 318B - /images -> http://scanme.nmap.org/images/ [12:31:40] 200 - 7KB - /index 
[12:31:40] 200 - 7KB - /index.html 
[12:31:53] 403 - 295B - /server-status 
[12:31:53] 403 - 296B - /server-status/ 
[12:31:54] 301 - 318B - /shared -> http://scanme.nmap.org/shared/
Task Completed
```
###### Gobuster’s Dir:
- used to find additional content on a specific domain or subdomain
- This includes hidden directories and files.
- In this mode, you can use the -u flag to specify the domain or subdomain you want to brute-force and -w to specify the wordlist you want to use:
```bash
gobuster dir -u target_url -w wordlist
```

- Manually visiting all the pages you’ve found through brute-forcing can be time-consuming
- Instead, use a screenshot tool like **==EyeWitness==** (https://github.com/FortyNorthSecurity/EyeWitness/) or **==Snapper==** (https://github.com/dxa4481/Snapper/) to automatically verify that a page is hosted on each location.
- EyeWitness accepts a list of URLs and takes screenshots of each page
- In a photo gallery app, you can quickly skim these to find the interesting-looking ones
- Keep an eye out for hidden services, such as developer or admin panels, directory listing pages, analytics pages, and pages that look outdated and ill-maintained.

---
##### Spidering the Site:
- Way of ***discovering directories and paths*** is through web spidering, or web crawling, a process used to identify all pages on a site.

1. A web spider tool starts with a page to visit.
2. It then identifies all the URLs embedded on the page and visits them
3. By recursively visiting all URLs found on all pages of a site, the web spider can uncover many hidden endpoints in an application.
###### OWASP Zed Attack Proxy (ZAP):
-  https://www.zaproxy.org/ has a built-in web spider you can use.
- This open source security tool includes a scanner, proxy, and many other features
- Burp Suite has an equivalent tool called the crawler.
![[Pasted image 20250926103233.png]]

1. Access its spider tool by opening ZAP and choosing Tools-->Spider
![[Screenshot 2025-09-26 103404.png]]
2. You should see a window for specifying the starting URL
![[Pasted image 20250926103836.png]]
3. Click Start Scan. You should see URLs pop up in the bottom window
![[Pasted image 20250926104016.png]]
4. You should also see a site tree appear on the left side of your ZAP window. This shows you the files and directories found on the target server in an organized format.
![[Pasted image 20250926104526.png]]

---
##### Third-Party Hosting
- Take a look at the company’s third-party hosting footprint.
- For example, look for the organization’s S3 buckets. S3, which stands for Simple Storage Service, is Amazon’s online storage product.
- Organizations can pay to store resources in buckets to serve in their web applications, or they can use S3 buckets as a backup or storage location.
- If an organization uses Amazon S3, its S3 buckets can contain hidden endpoints, logs, credentials, user infor mation, source code, and other information that might be useful to you.

###### How do you find an organization’s buckets?
- One way is through Google dorking, as mentioned earlier
- Most buckets use the URL format BUCKET .s3.amazonaws.com or s3.amazonaws.com/BUCKET, so the following search terms are likely to find results:
```
site:s3.amazonaws.com COMPANY_NAME 
site:amazonaws.com COMPANY_NAME
```
- If the company uses custom URLs for its S3 buckets, try more flexible search terms instead.
- Companies often still place keywords like aws and s3 in their custom bucket URLs, so try these searches:
```
amazonaws s3 COMPANY_NAME 
amazonaws bucket COMPANY_NAME 
amazonaws COMPANY_NAME 
s3 COMPANY_NAME
```
- Another way of finding buckets is to search a company’s public GitHub repositories for S3 URLs.
- GrayhatWarfare (https://buckets.grayhatwarfare.com/) is an online search engine you can use to find publicly exposed S3 buckets
	- It allows you to search for a bucket by using a keyword.
	- Supply keywords related to your target, such as the application, project, or organization name, to find relevant buckets
![[Pasted image 20250927123701.png]]

- **Lazys3**
	- you can try to brute-force buckets by using keywords. Lazys3 (https://github.com/nahamsec/lazys3/) is a tool that helps you do this.
	- It relies on a wordlist to guess buckets that are permutations of common bucket names.
- **Bucket Stream**
	- Another good tool is Bucket Stream (https://github.com/eth0izzle/bucket-stream/), which parses certificates belonging to an organization and finds S3 buckets based on permutations of the domain names found on the certificates.
	- Bucket Stream also automatically checks whether the bucket is accessible, so it saves you time.

- you’ve found a couple of buckets that belong to the target organi zation, use the AWS command line tool to see if you can access one.
```bash
pip install awscli
```
- Then configure it to work with AWS by following Amazon’s documentation at https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html.
- Now you should be able to access buckets directly from your terminal via the aws s3 command. Try listing the contents of the bucket you found:
```bash 
aws s3 ls s3://BUCKET_NAME/
```
- If this works, see if you can read the contents of any interesting files by copying files to your local machine:
```bash
aws s3 cp s3://BUCKET_NAME/FILE_NAME/path/to/local/directory
```
- Gather any useful information leaked via the bucket and use it for future exploitation
- If the organization reveals information such as active API keys or personal information, you should report this right away.
- Exposed S3 buck ets alone are often considered a vulnerability
- You can also try to upload new f iles to the bucket or delete files from it. If you can mess with its contents, you might be able to tamper with the web application’s operations or corrupt company data.
- For example, this command will copy your local file named TEST_FILE into the target’s S3 bucket:
```bash
aws s3 cp TEST_FILE s3://BUCKET_NAME/
```
- And this command will remove the TEST_FILE that you just uploaded:
```bash
aws s3 rm s3://BUCKET_NAME/TEST_FILE
```

> These commands are a harmless way to prove that you have write access to a bucket without actually tampering with the target company’s files.

> Always upload and remove your own test files. Don’t risk deleting important company resources during your testing unless you’re willing to entertain a costly lawsuit
##### GitHub Recon
- Search an organization’s ***GitHub repositories for sensitive data*** that has been accidentally committed, or information that could lead to the discovery of a vulnerability.
- Start by finding the GitHub usernames relevant to your target.
- You should be able to locate these by searching the organization’s name or product names via GitHub’s search bar, or by checking the GitHub accounts of known employees.
1. When you’ve found usernames to audit, visit their pages. Find repositories related to the projects you’re testing and record them, along with the usernames of the organization’s top contributors, which can help you find more relevant repositories.
2. Then dive into the code. For each repository, pay special attention to the Issues and Commits sections.
3. These sections are full of potential info leaks: ==they could point attackers to unresolved bugs, problematic code, and the most recent code fixes and security patches.==
4. **Recent code changes** that haven’t stood the test of time are more likely to contain bugs.
5. Look at any ==protection mechanisms implemented== to see if you can bypass them.
6. You can also search the Code section for potentially vulnerable code snippets.
7. Once you’ve found a file of interest, **check the Blame and History sections at the top-right corner of the file’s page to see how it was developed.**
8. look for hardcoded secrets such as ==API keys, encryption keys, and database passwords. terms like key, secret, and password==
9. After you’ve found leaked credentials, you can use KeyHacks (https://github.com/streaak/keyhacks/) to ==check if the credentials are valid and learn how to use them to access the target’s services==.
10. You should also search for ==sensitive functionalities== in the project. See if any of the source code deals with important functions ==such as authentication, password reset, state-changing actions, or private info reads.==
11. Pay attention to code that deals with user input, ==such as HTTP request parameters, HTTP headers, HTTP request paths, database entries, file reads, and file uploads,== because they provide potential entry points for attackers to exploit the application’s vulnerabilities.
12. Look for ==any configuration files==, as they allow you to gather more information ==about your infrastructure==
13. Search for ==old endpoints and S3 bucket URLs== that you can attack.
14. ==Outdated dependencies and the unchecked use of dangerous functions== are also a huge source of bugs.
15. Pay attention to ==dependencies and imports being used and go through the versions list== to see if ==they’re outdated.==

> Record any outdated dependencies. You can use this information later to look for publicly disclosed vulnerabilities that would work on your target

16. Tools like Gitrob and TruffleHog can automate the GitHub recon process.
	- **==Gitrob==** (https://github.com/michenriksen/gitrob/) locates potentially sensitive f iles pushed to public repositories on GitHub.
	- **==TruffleHog==** (https://github.com/ trufflesecurity/truffleHog/) specializes in finding secrets in repositories by con ducting regex searches and scanning for high-entropy strings.

---
##### Other Sneaky OSINT Techniques
- First, check the company’s job posts for engineering positions.
- Engineering job listings often reveal the technologies the company uses.
- For example, take a look at an ad like this one: 
	- **Full Stack Engineer** 
		- Minimum Qualifications: 
		- Proficiency in Python and C/C++ 
		- Linux experience 
		- Experience with Flask, Django, and Node.js 
		- Experience with Amazon Web Services, especially EC2, ECS, S3, and RDS
> From reading this, you know the company uses Flask, Django, and Node.js to build its web applications. The engineers also probably use Python, C, and C++ on the backend with a Linux machine. Finally, they use AWS to outsource their operations and file storage.
- If you can’t find relevant job posts, search for ==employees’ profiles on LinkedIn,== and ==read employees’ personal blogs or their engineering questions on forums== like ==Stack Overflow and Quora==.
- Another source of information is the ==employees’ Google calendars==. People’s work calendars often ==contain meeting notes, slides, and some times even login credentials.==
- If an employee ==shares their calendars with the public by accident==, you could gain access to these. The ==organization or its employees’ social media pages== might also leak valuable information.
>For example, hackers have actually discovered sets of valid credentials on Post-it Notes visible in the background of office selfies!
- If the company has an ==engineering mailing list, sign up== for it to gain insight into the ==company’s technology and development process==.
- Also check the ==company’s SlideShare or Pastebin accounts.== Sometimes, when ==organizations present at conferences or have internal meetings, they upload slides to SlideShare for reference==. You might be able to find information about ==the technology stack and security challenges faced by the company.==
- **==Pastebin==** (https://pastebin.com/) is a website for pasting and storing text online for a short time.
- People use it to share text across machines or with others. Engineers sometimes ==use it to share source code or server logs with their colleagues for viewing or collaboration,== so it could be a great source of information.
- You might also ==find uploaded credentials and development comments.==
- Go to Pastebin, ==search for the target’s organization name, and see what happens==! You can also ==use automated tools like **PasteHunte**==r (https://github.com/kevthehermit/PasteHunter/) to scan for publicly pasted data.

- consult archive websites like the **==Wayback Machine==** (https://archive.org/web/), a digital record of internet content.
- It records a site’s content at various points in time. Using the Wayback Machine, you can ==find old endpoints, directory listings, forgotten subdomains, URLs, and files that are outdated but still in use.==
- ==**Tomnomnom’s tool Waybackurls**== (https://github.com/tomnomnom/waybackurls/) can automatically extract end points and URLs from the Wayback Machine.

![[Pasted image 20250927143611.png]]

---
##### Tech Stack Fingerprinting
- Fingerprinting is identifying the software brands and versions that a machine or an application uses.
- This information allows you to per form targeted attacks on the application, because you can search for ==any known misconfigurations and publicly disclosed vulnerabilities related to a particular version.==
- For example, if you know the server is using an old version of Apache that could be impacted by a disclosed vulnerability, you can immediately attempt to attack the server using it.
- The security community classifies known vulnerabilities as Common Vulnerabilities and Exposures (CVEs) and gives each CVE a number for reference.
- Search for them on the CVE database (https://cve.mitre.org/cve/search_cve_list.html).
- First, run ==**Nmap**== on a machine with the -sV flag on to enable version detection on the port scan.
```bash
$ nmap scanme.nmap.org -sV 
Starting Nmap 7.60 ( https://nmap.org ) 
Nmap scan report for scanme.nmap.org (45.33.32.156) 
Host is up (0.065s latency). 
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f 
Not shown: 992 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0) 
25/tcp filtered smtp 
80/tcp open http Apache httpd 2.4.7 ((Ubuntu)) 
135/tcp filtered msrpc 
139/tcp filtered netbios-ssn 
445/tcp filtered microsoft-ds 
9929/tcp open nping-echo Nping echo 
31337/tcp open tcpwrapped 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/. 
Nmap done: 1 IP address (1 host up) scanned in 9.19 seconds
```
- Next, in ==Burp==, send an HTTP request to the server to check the HTTP headers used to gain insight into the tech stack.
- A server might leak many pieces of information useful for fingerprinting its technology:
```
Server: Apache/2.0.6 (Ubuntu) 
X-Powered-By: PHP/5.0.1 
X-Generator: Drupal 8 
X-Drupal-Dynamic-Cache: UNCACHEABLE 
Set-Cookie: PHPSESSID=abcde;
```

 - HTTP headers like Server and X-Powered-By are good indicators of technologies.
-  The Server header often reveals the software versions running on the server. X-Powered-By reveals the server or scripting language used.
- Certain ==headers are used only by specific technologies==. For example, only ==Drupal uses X-Generator and X-Drupal-Dynamic-Cache.==
- Technology-specific cookies such as PHPSESSID are also clues; if a server sends back a ==cookie named PHPSESSID==, it’s probably ==developed using PHP.==
- The HTML source code of web pages can also provide clues. Many web frameworks or other technologies will embed a signature in source code.
- Right-click a page, ==select View Source Code,== and press CTRL-F to search for phrases like ==powered by, built with, and running==. For instance, you might find Powered by: WordPress 3.3.2 written in the source.
- Check technology-specific ==file extensions, filenames, folders, and directories.== For example, a ==file named phpmyadmin at the root directory==, like https://example.com/phpmyadmin, means the application runs PHP.
- A ==directory named jinja2== that contains templates means the site probably uses ==Django and Jinja2.==
- **==Wappalyzer==** (https://www.wappalyzer.com/) is a browser extension that identifies content management systems, frameworks, and programming languages used on a site.
- **==BuiltWith==** (https://builtwith.com/) is a website that shows you which web technologies a site is built with.
- **==StackShare==** (https://stackshare.io/) is an online platform that allows developers to share the tech they use. You can use it to find out if the organization’s developers have posted their tech stack
- **==Retire.js==** is a tool that detects outdated JavaScript libraries and Node.js pack ages. You can use it to check for outdated technologies on a site.

#### TOOLS:
##### Scope Discovery
- WHOIS looks for the owner of a domain or IP. 
- ViewDNS.info reverse WHOIS (https://viewdns.info/reversewhois/) is a tool that searches for reverse WHOIS data by using a keyword. 
- nslookup queries internet name servers for IP information about a host. 
- ViewDNS reverse IP (https://viewdns.info/reverseip/) looks for domains hosted on the same server, given an IP or domain. 
- crt.sh (https://crt.sh/), Censys (https://censys.io/), and Cert Spotter (https:// sslmate.com/certspotter/) are platforms you can use to find certificate information about a domain. 
- Sublist3r (https://github.com/aboul3la/Sublist3r/), SubBrute (https://github .com/TheRook/subbrute/), Amass (https://github.com/OWASP/Amass/), and Gobuster (https://github.com/OJ/gobuster/) enumerate subdomains. 
- Daniel Miessler’s SecLists (https://github.com/danielmiessler/SecLists/) is a list of keywords that can be used during various phases of recon and hacking. For example, it contains lists that can be used to brute-force subdomains and filepaths. 
- Commonspeak2 (https://github.com/assetnote/commonspeak2/) generates lists that can be used to brute-force subdomains and filepaths using publicly available data. 
- Altdns (https://github.com/infosec-au/altdns) brute-forces subdomains by using permutations of common subdomain names. 
- Nmap (https://nmap.org/) and Masscan (https://github.com/robertdavidgraham/ masscan/) scan the target for open ports. 
- Shodan (https://www.shodan.io/), Censys (https://censys.io/), and Project 
- Sonar (https://www.rapid7.com/research/project-sonar/) can be used to find services on targets without actively scanning them. 
- Dirsearch (https://github.com/maurosoria/dirsearch/) and Gobuster (https:// github.com/OJ/gobuster) are directory brute-forcers used to find hidden filepaths. 
- EyeWitness (https://github.com/FortyNorthSecurity/EyeWitness/) and Snapper (https://github.com/dxa4481/Snapper/) grab screenshots of a list of URLs. They can be used to quickly scan for interesting pages among a list of enumerated paths. 105 Web Hacking Reconnaissance   
- OWASP ZAP (https://owasp.org/www-project-zap/) is a security tool that includes a scanner, proxy, and much more. Its web spider can be used to discover content on a web server. 
- GrayhatWarfare (https://buckets.grayhatwarfare.com/) is an online search engine you can use to find public Amazon S3 buckets. 
- Lazys3 (https://github.com/nahamsec/lazys3/) and Bucket Stream (https:// github.com/eth0izzle/bucket-stream/) brute-force buckets by using keywords.

##### OSINT
- The Google Hacking Database (https://www.exploit-db.com/google -hacking-database/) contains useful Google search terms that fre quently reveal vulnerabilities or sensitive files. 
- KeyHacks (https://github.com/streaak/keyhacks/) helps you determine whether a set of credentials is valid and learn how to use them to access the target’s services. 
- Gitrob (https://github.com/michenriksen/gitrob/) finds potentially sensitive files that are pushed to public repositories on GitHub. 
- TruffleHog (https://github.com/trufflesecurity/truffleHog/) specializes in finding secrets in public GitHub repositories by searching for string patterns and high-entropy strings. 
- PasteHunter (https://github.com/kevthehermit/PasteHunter/) scans online paste sites for sensitive information. 
- Wayback Machine (https://archive.org/web/) is a digital archive of internet content. You can use it to find old versions of sites and their files. 
- Waybackurls (https://github.com/tomnomnom/waybackurls/) fetches URLs from the Wayback Machine

##### Tech Stack Fingerprinting
- The CVE database (https://cve.mitre.org/cve/search_cve_list.html) contains publicly disclosed vulnerabilities. You can use its website to search for vulnerabilities that might affect your target. 
- Wappalyzer (https://www.wappalyzer.com/) identifies content manage ment systems, frameworks, and programming languages used on a site. 
- BuiltWith (https://builtwith.com/) is a website that shows you which web technologies a website is built with. 
- StackShare (https://stackshare.io/) is an online platform that allows devel opers to share the tech they use. You can use it to collect information about your target. 
- Retire.js (https://retirejs.github.io/retire.js/) detects outdated JavaScript libraries and Node.js packages

##### Automation
- Git (https://git-scm.com/) is an open sourced version-control system. You can use its git diff command to keep track of file changes.

>You can try to leverage recon platforms like Nuclei (https://github.com/projectdiscovery/nuclei/) or Intrigue Core (https://github.com/intrigueio/intrigue-core/) to make your recon process more efficient.

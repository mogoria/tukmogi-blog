---
title: AspireCTF Web Challenge
author: "tukmogi"
tags: ["Aspire", "CTF"]
categories: ["aspire", "web"]
date: 2021-04-06
featured_image: "/images/aspire-ctf-web/aspire-web-thumb.png"
---
## Introduction

This is a writeup on the Web Challenge of the Aspire CTF - 2021.

## AgentX

### Challenge Description: Where are you from?

Challenge site
![Challenge Site](/images/aspire-ctf-web/4-2.png)
The paste contained the ips below

```bash
62.210.105.116
51.77.135.89
171.25.193.78
171.25.193.20
185.220.101.208
171.25.193.77
185.165.168.229
185.220.102.8
162.247.72.199
107.189.10.27
106.12.102.21
```

Following the access link, there is a PHP page that displays the IP address and errors out, Invalid Access! We can try to find out how developers access the IP address of a client. An interesting find is that there are headers used by proxies to identify the client sending the request. That is the X-FORWARDED-FOR header and the CLIENT-IP header. Trying out a request with the X-FORWARDED-HOST header set, we see that we can now manipulate the client IP.

```bash
curl -s -H 'x-forwarded-for: localhost' http://45.32.238.36/agentX/access.php ; echo
```

![Agentx curl](/images/aspire-ctf-web/4-3.png)
Using the IPs obtained from the paste, we can try and brute-force for valid ones. Wfuzz was used for this but Burp Suite’s intruder could also work.

```bash
wfuzz -c -w clients.txt -H 'x-forwarded-for: FUZZ' http://45.32.238.36/agentX/access.php
```

![Agentx flag](/images/aspire-ctf-web/4-4.png)
Another note is that, since the site reflects data sent from the X-FORWARDED-FOR and CLIENT-IP headers, it's vulnerable to Cross-Site Scripting (XSS). We can confirm this by trying out the payload: ```X-FORWARDED-FOR: <script>alert(document.domain)</script>```

## Cookie Jar

### Challenge Description: The admin has your flag

Accessing the challenge site hints at a role-based website, admin privilege is needed to access the page.
![](/images/aspire-ctf-web/5-2.png)

Cookies are used to store content on the browser and are forwarded to the server on each request. Some authentication systems use cookies to automatically handle authentication. Checking out cookies on the website, we see that there is a cookie value called role.
![](/images/aspire-ctf-web/5-3.png)
Changing this value to admin and refreshing, the page, we get the flag.
![](/images/aspire-ctf-web/5-4.png)

## Filer

### Challenge Description: Find the vulnerability, look around and you'll find the flag! Can you access our passwords?

Assessing the challenge site, we get this page.
![](/images/aspire-ctf-web/6-2.png)
We can try and find out the valid parameters on the website. Using the extension Param Miner on Burp Suite, we can try and find parameters on the website. Right-click on a request then click on ‘Guess GET parameters’, on the extensions tab, we get output from param miner. There is a valid parameter found called ‘file’.
![](/images/aspire-ctf-web/6-3.png)
Arjun can also be used.
Passing a file name to the parameter displays it and that’s how we get the flag.
![](/images/aspire-ctf-web/6-4.png)

## Method man

### Challenge Description: The admin is particularly fond of numbers below 200. Find what he has hidden

Accessing the challenge site, we find this.
![](/images/aspire-ctf-web/7-2.png)
Once more, using param miner or Arjun, we discover a parameter called code.
![](/images/aspire-ctf-web/7-3.png)
Passing code 1, the page doesn’t display any content. Based on the hint from the home page, we can tell that the code could be anything between 1 and 200
![](/images/aspire-ctf-web/7-4.png)
We can use Burp Suite intruder to brute force for the right code. Send the request to Intruder, on the payloads tab, specify numbers as the payload type as numbers. Set the payload options to run from 1 to 200 and step once.
![](/images/aspire-ctf-web/7-5.png)
Filter the results by length. From that, we find that two requests are unique. Viewing the response of code 79, we find our flag.
![](/images/aspire-ctf-web/7-6.png)
Wfuzz can also be used to brute-force for the code since Burp intruder tends to be slow when using the community edition.
![](/images/aspire-ctf-web/7-7.png)

## Words

### Words1: Our developer left something for you. Find it

Accessing the challenge site, we find a webpage.
![](/images/aspire-ctf-web/8-2.png)
Based on the hint, we can create a wordlist on extensions for common backup files, configuration files and archives.

```bash
bak
bk
config
cfg
tar
tar.gz
tar.xz
zip
```

We can then use raft-medium-words.txt wordlists from Seclists together with our extension lists to brute force for anything left by the developer.

```bash
wfuzz -c --hc 404,403 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -w extensions.txt http://144.202.34.159/words/FUZZ.FUZ2Z 
```

![](/images/aspire-ctf-web/wfuzz_word_one.png)
We get the flag by accessing: <http://144.202.34.159/words/.env.bak>
![](/images/aspire-ctf-web/word1_env_bak.png)

Nothing else could be found at the challenge site with popular wordlists. We can create a wordlist using words retrieved from the website using cewl. Cewl manages to generate a wordlist with 43 words.

```bash
cewl -w custom_wordlist.txt http://144.202.34.159/words/ 
```

![](/images/aspire-ctf-web/8-3.png)

Using the custom wordlist, we discover two new paths.

```bash
wfuzz -c --hc 404 -w custom_wordlist.txt http://144.202.34.159/words/FUZZ/ 
```

![](/images/aspire-ctf-web/8-4.png)

Navigating to one of the discovered paths, computerphIles, we get this page.
![](/images/aspire-ctf-web/8-6.png)
We are told that vim was used to edit the page. Vim creates a swap file when editing a file in the form ‘.filename.swp’ for recovery purposes. This also prevents multiple instances of vim editing the same file. More information can be read here. Since our main file is index.html, the vim swap file would be ‘.index.html.swp’. Accessing this via the browser shows no content change but if we view the source code, we obtain the flag.

![](/images/aspire-ctf-web/8-7.png)

Accessing the other discovered path, we get this webpage.
![](/images/aspire-ctf-web/8-9.png)

Using our cewl wordlist together with seclists mosts common extensions, we get an archive, compartmentalize.tar.gz.
![](/images/aspire-ctf-web/8-10.png)
Downloading and extracting the archive, we get a flag.txt with our flag in it.
![](/images/aspire-ctf-web/8-11.png)

## Executor

### Challenge Description: A vulnerability exists. Find it and get the flag

We didn’t manage to solve this challenge within the ctf period. Accessing the challenge site yields a blank page with pre tags.
![](/images/aspire-ctf-web/9-1.png)
Using arjun, we discover ip parameter
![](/images/aspire-ctf-web/9-2.png)
Specifying localhost as the payload, we get ping statistics for localhost. Sweet, we can now try and find command injection vulnerability
![](/images/aspire-ctf-web/9-5.png)
Chaining the commands finally worked using pipe.
![](/images/aspire-ctf-web/9-6.png)
Displaying the txt file using cat but it didn’t work. Time to figure out why. Possibly there is a WAF filtering our requests.
![](/images/aspire-ctf-web/9-7.png)
 Turns out the word cat is filtered out. This can be bypassed in different ways. One way could be using ‘cacatt’ so that even after filtering out, its still valid. What if ‘cat’ is recursively filtered out, this wouldn’t work. There are a couple of evasion techniques to try out from secjuice, payload all the things and many more.
![](/images/aspire-ctf-web/9-8.png)

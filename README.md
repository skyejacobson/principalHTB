# Principal HTB
Personal writeup of the Principal hack the box machine

Initial nmap scan reveals 2 PoA on the machine
```
┌──(root㉿kali-linux-2024-2)-[/home/parallels/Documents/Principal]
└─# nmap -sV -sC 10.129.39.147 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-25 19:59 +0900
Stats: 0:00:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 20:00 (0:00:29 remaining)
Nmap scan report for 10.129.39.147
Host is up (0.41s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sat, 25 Apr 2026 10:59:04 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-04-25T10:59:04.048+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     Date: Sat, 25 Apr 2026 10:59:01 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 25 Apr 2026 10:59:02 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch: 
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Sat, 25 Apr 2026 10:59:03 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 505 Unknown Version</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5: 
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 25 Apr 2026 10:59:04 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>
```

Adding the ip to hosts to searching in the URL via 8080 brings up a website with a login for Principal Internal Platform. We can enumerate further via `fuff`.

Nothing of note comes up besides a 200 on a page called `dashboard`. Attempting to access the page commits an autoredirect to login. Something that can be used later.


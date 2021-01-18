`console and cannot use BurpSuite:
* * EX: openssl s_client -connect targetSite.com:443
* * flag -quiet to stop it from using verbose mode
* * Once connected we can do OPTIONS to see what's allowed, PUT can allow us to put a shell on the target

# Standard Cookies (local/ client-side)
* If cookie domain is not specified it will be restrcited to just the immediate server and will not pass to other sub.domains.com.
* Adding 'http.only' flag when setting up a cookie pervents against XSS and other attacks that might allow reading of that cookie.
* Adding 'secure' flag in a cookie will only send cookies on HTTPS connections
* When hijacking cookies, first make an init request to have the site generate us a cookie, THEN we can manipulate that and insert our own before submitting a GET request to the site with the weaponized cookie

### Session Cookies (server-side)
* Slightly less secure to hide some of how the site functions, token-based
* Can be submitted through GET links, EX: https://coolsite.com/index.php&sessid=kw3r9
* PHP Sites use: PHPSESSID
* JSP Sites use: JSESSIONID
* Web dev can set their own custom parameters though instead of the examples above for PHP & JSP.


* So biggest differecnes between HTTP and HTTPS are within the ssl/tls handshake

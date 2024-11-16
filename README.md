nginx-ipbind-module
=============
Records each URL's first successful access IP in shared memory zone. Restricts other IPs access to the same URL.

## Installation
Specify while building Nginx
```
$ ./configure --add-module=../nginx-ipbind-module/
```

## Configuration
```
ipbind_zone one 256m;
<...>
location /protected/ {
   ipbind one;
}
```

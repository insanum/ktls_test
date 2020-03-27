# ktls_test
TLS v1.2/1.3 echo client/server application using wolfSSL that supports KTLS offload.

```
To compile this application simply run the 'build.sh' script.

There are three applications:
    - tls_server (supports TLSv1.2 and TLSv1.3)
    - tls_client_12 (supports TLSv1.2 only)
    - tls_client_13 (supports TLSv1.3 only)

Usage: ./tls_server [ -t ] [ -b <size> ]
  -h         this usage info
  -t         enable TCP cork (default off)
  -k <dir>   KTLS direction (tx|rx|all|none) (default none)
  -b <size>  send buffer size (default 32768)
  -p <port>  port to bind to (default 4433)

Usage: ./tls_client_12 [-t] [-k <dir>] [-b <size>] [-p <port>] -s <ip>
  -h         this usage info
  -t         enable TCP cork (default off)
  -k <dir>   KTLS direction (tx|rx|all|none) (default none)
  -a <aes>   AES key size (128|256) (default 128)
  -b <size>  send buffer size (default 32768)
  -p <port>  server port to connect to (default 4433)
  -s <ip>    server IP to connect to
```

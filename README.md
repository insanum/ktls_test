
# KTLS Test

This application implements an echo client/server that operates over
TLS 1.2 and TLS 1.3. Various arguments are used to configure the flow
allowing for deterministic placement of TLS record headers and authentication
tags across packets.

The main feature of this application is its ability to offload the flow
using Linux Kernel TLS (KTLS). If the Ethernet driver support KTLS hardware
offload then the flow will get offload further from the kernel to the NIC.

## Building

The TLS protocol and AES-GCM support is provided by
[wolfSSL](https://github.com/wolfSSL/wolfssl). The `ktls_test` build script
will automatically download, patch, configure, and build wolfSSL. Note that
the wolfSSL library does not support dynamic control of TLS 1.2 vs 1.3 on the
client (i.e. connect) side of the socket. Therefore multiple client side
binaries are built.

The `build.sh` script without any arguments builds all three binaries:
```
% ./build.sh
```

Individual binaries can be re-compiled with the following targets:
```
% ./build.sh server
% ./build.sh clients
% ./build.sh client_12
% ./build.sh client_13
```

The resulting `ktls_test` binaries are:
- `tls_server` - supports both TLS 1.2/1.3
- `tls_client_12` - for TLS 1.2
- `tls_client_13` - for TLS 1.3

## Usage

Below is the usage for the server and clients. Note that `root` is NOT
required to run these applications.

### TCP Cork

When sending data over a TCP socket there is no guarantee how the data
being sent is populated across packets. When the window is open all pending
data could be sent immediately in full sized packets. If the window is small
then only a partial amount of the pending data could be sent. The point is
for the flow, as it's seen on the wire, will not be deterministic based on
the socket send calls made by the application. It is very common to see
different packet sequences captured across multiple tests for the same exact
data sent.

This behavior is problematic for unit testing specific KTLS edge cases where
TLS record headers and authentication tags need to be located at the
beginning, in the middle, or at the end of a packet. Even further whether or
not the header or tag is sent in multiple packets by crossing a packet
boundary.

In order to test these various conditions we must have some control over
how TCP sends the data on the socket. Determinism can be achieved on Linux
as the TCP/IP stack supports the `TCP_CORK` socket option:

> TCP_CORK (since Linux 2.2)
> If set, don't send out partial frames. All queued partial frames are sent
> when the option is cleared again. This is useful for prepending headers
> before calling sendfile(2), or for throughput optimization. As currently
> implemented, there is a 200 millisecond ceiling on the time for which
> output is corked by TCP_CORK. If this ceiling is reached, then queued
> data is automatically transmitted.

Corking a socket allows us to pile up a ton of data on the socket at the
TCP layer before it's packetized and sent to the NIC. This allows us to send
a continuous stream of full-sized packets and based on the record size,
deterministically place where the TLS headers and tags live across the packet
stream.

When `TCP_CORK` is enabled, the client blasts all its data over multiple
send calls in a tight loop. After all data is sent, the client will then start
receiving the data back from the server. If left unchecked this sequence of
events can lead to a TCP deadlock on the connection. Both the client and
server can be stuck in send while their receive windows are full (i.e. no
calls are being made to receive data off the socket, the application is single
threaded). To mitigate this problem, whenever `TCP_CORK` is enabled the data
length to send is automatically capped to the maximum window size.

### Server:

```
% ./tls_server -h
Usage: ./tls_server [ <arguments> ] [ -b <size> ]
  -h         this usage info
  -T         enable TCP cork (default off)
  -k <dir>   KTLS direction (tx|rx|all|none) (default none)
  -b <size>  send buffer size (default 32768)
  -p <port>  port to bind to (default 4433)
``` 

The port number that the server binds to is 4433. This can be modified using
the `-p` option.

Note that at this time the server is single threaded. While the code is
structured in a way to easily spawn a thread per client connection, it was
not implemented as this application targets general and specific edge cases
for KTLS testing, not performance.

By default KTLS is not used for offloading TLS to the kernel and/or hardware
devices. This allows the server to be tested in a non-KTLS manner while the
client peer could possible be using KTLS. Use the `-k` option to specify
the direction of the flow to offload (i.e. rx/tx/both).

The buffer size `-b` is used for both the `recv()` and `send()` calls on the
socket. If the server has a buffer size of 2000 and the client uses only 1000
but has enabled `TCP_CORK`, the server will receive full 2000 byte buffers
of data. If `TCP_CORK` was not being used by the client then the server will
only receive 1000 bytes per `recv()` call.

Enabled `TCP_CORK` on the server has a minor affect on the behavior seen on
the flow. If the client is using `TCP_CORK` then the server will be receiving
and sending data much quicker and full-size packets will be seen coming from
the server. If `TCP_CORK` is disabled then it's common to see some less than
full-sized packets sprinkled throughout the stream. If the client is not using
`TCP_CORK` then there is no affect whatsoever on the server side since the
client is operating in a send/receive/repeat manner until all data has been
sent.

### Client:

```
% ./tls_client_12 -h
Usage: ./tls_client_12 [ <arguments> ] -s <ip>
  -h           this usage info
  -T           enable TCP cork (default off)
  -t           send all data then receive (default send/recv/repeat)
  -q           quiet, don't print out received data
  -k <dir>     KTLS direction (tx|rx|all|none) (default none)
  -a <aes>     AES key size (128|256) (default 128)
  -b <size>    send buffer (record) size (default 32768)
  -r <max>     use random send buffer (record) sizes (0..<max>)
  -g <length>  generate 'length' bytes (default stdin)
  -p <port>    server port to connect to (default 4433)
  -s <ip>      server IP to connect to
```

There are number of additional options available to the client that aren't
available on the server side. This is because the client application drives
most of the characteristics of the flow.

There are two client applications. `tls_client_12` is used for TLS 1.2 flows
and `tls_client_13` is used for TLS 1.3 flows. The available arguments are
the same between them. The AES key size used by TLS can also be modified
with the `-a` argument switching between AES-128 and AES-256.

The data to be sent from by the client can come from one of three different
sources:
1. **stdin** - A file or any other kind of generated data can be piped
   directly to the client via the shell on the command line. The client
   will continuously read and send data from the pipe until EOF is seen.
2. **interactive** - In this case the client still reads data from stdin
   but the data is manually entered by the user. Each line of data (i.e. up
   until `\n`) is sent on its own to the server. Exit the client application
   with `CTRL-C`.
3. **generated** - The client will automatically generate data to be sent.
   For each `bufsize` amount of data to send the client fills the entire
   buffer with a single character. The initial character is `a` and it is
   incremented for each buffer sent. The value wraps at `z`. This method is
   nice since the alignment of initially sent record data received from the
   server can be seen as it's printed to the stdout after each receive call.

Note that the client prints to stdout all the data it receives back from the
server. If the data being sent isn't ASCII then the terminal can get
corrupted. In this case use the `-q` option to prevent the data from be
printed to stdout.

By default when `TCP_CORK` is NOT enabled the client runs in a
send/receive/repeat loop until all data has been sent. When `TCP_CORK` is
enabled the client does a send all data followed by receive all data. This
second method can be achieved without enabling `TCP_CORK` with the `-t`
option. With `-t` there is still no guarantee that full-sized packets will
be sent but this option does offer another mode of test that has different
characteristics.

The buffer size `-b` is used for both the `send()` and `recv()` calls on the
socket. On the send side the amount of data sent in a `send()` call is exactly
the TLS record size generated. If the client uses a buffer size of 2000 then
TLS records of length 2000 bytes will be sent. What the server receives in
its `recv()` call is dependent on its own buffer size. The buffer size used
in combination with `TCP_CORK` allows TLS headers and tags to be placed in
specific locations with respect to the packets generated for the flow.
Alternatively the `-r` argument can be used instead of `-b` which results
in the client send random sized TLS records up to the max specified. This
mode is obviously not deterministic but definitely can create some odd
situations.

The easiest way to use the client is to have it generate its own data to be
sent. This is achieved with the `-g` option. The length given to this argument
represents the total data length to send and is independent of the buffer
size. Generated data is made up of ASCII lower case characters. The first
TLS record contains all `a`'s and the second all `b`'s, etc. The fill
character used wraps at `z`. The method allows the user to easily see the
returned record data and how it is lining up across calls to `recv()`.

## Examples

Below are a number of examples that demonstrate the various use cases for
`ktls_test` and how it can be configured to test specific edge cases of
TLS offloaded flows. They range from very basic to highly complex.

For these examples assume the server is the SUT that has the ability to
offload TLS flows to a hardware device.

Lastly, assume the MTU is 1500. With TCP this results in 1448 bytes of payload
per packet for TLS protocol data.

----

Basic user interactive input with no offload.

> ```
> Server:
> % tls_server
>
> Client:
> % tls_client_12 -s 172.16.0.2
> ```

----

Send file data with no offload.

> ```
> Server:
> % tls_server
>
> Client:
> % cat file.txt | tls_client_12 -s 172.16.0.2
> ```

----

Send 8K of generated data with no offload and a 2K buffer size.

> ```
> Server:
> % tls_server -b 2000
>
> Client:
> % tls_client_12 -s 172.16.0.2 -b 2000 -g 8192
> ```

----

Send 8K of generated data with no offload and TCP cork. Use different buffer
sizes on the client/server resulting in different TLS record lengths used
in each direction.

> ```
> Server:
> % tls_server -T -b 2000
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -b 1000 -g 8192
> ```

----

Send 32K of generated data with no offload, TCP cork, and random buffer sizes
(1..8K) on the client. With TCP cork enabled, the traffic from the server to
the client will utilize record sizes aligning with the server's buffer size.

> ```
> Server:
> % tls_server -T -b 2000
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 32768 -r 8192
> ```

----

Send 32K of generated data with TLS Rx offload and TCP cork.

> ```
> Server:
> % tls_server -T -k rx
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 32768
> ```

----

Send 32K of generated data with TLS tx offload, TCP cork, and 8K buffer
sizes.

> ```
> Server:
> % tls_server -T -k tx -b 8000
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 32768 -b 8000
> ```

----


Send 64K of generated data with full TLS offload.

> ```
> Server:
> % tls_server -T -k all
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 65536
> ```

----

Send exactly 2x TLS records each 1024 bytes in size.

> ```
> Server:
> % tls_server -T -k all
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 2048 -b 1024
> ```

----

Send exactly 2x TLS records where the header for the second record sent
crosses packet boundaries. With a 1448 payload, 13 header bytes for TLS 1.2,
and 16 tag bytes... the record length must be between 1407 and 1418 bytes
which forces the second header to cross the boundary between the first and
second packets.

1. pkt1 (1448 byte payload):
    - 13 header (rec1)
    - 1407 data
    - 16 tag
    - 12 header (rec2)
2. pkt2 (1424 byte payload):
    - 1 header (rec2)
    - 1407 data
    - 16 tag

> ```
> Server:
> % tls_server -T -k rx
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 2814 -b 1407
> ```

----

Send exactly 3x TLS records where the tags for the records sent crosses
packet boundaries. This example uses larger record sizes (approx two packets
in size) and if more records were sent the tags will eventually shift to
the point where they don't cross packet boundaries anymore.

1. pkt1 (1448 byte payload):
    - 13 header (rec1)
    - 1435 data
2. pkt2 (1448 byte payload):
    - 1436 data
    - 12 tag
3. pkt3 (1448 byte payload):
    - 4 tag
    - 13 header (rec2)
    - 1431 data
4. pkt4 (1448 byte payload):
    - 1440 data
    - 8 tag
5. pkt5 (1448 byte payload):
    - 8 tag
    - 13 header (rec3)
    - 1427 data
6. pkt6 (1448 byte payload):
    - 1444 data
    - 4 tag
7. pkt7 (12 byte payload):
    - 12 tag

> ```
> Server:
> % tls_server -T -k rx
>
> Client:
> % tls_client_12 -s 172.16.0.2 -T -g 8613 -b 2871
> ```

----

## Updating Test Certificates

The currently checked in certificates will work until end of 2034.
After that they can be regenerated with:

## CA Certificate

```shell
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout certs/ca-key.pem -out certs/ca-cert.pem -subj \
    "/CN=Test CA"
```

## Server Certificate

```shell
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
    -keyout certs/server-key.pem -out certs/server-cert.pem \
    -subj "/CN=example.com" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

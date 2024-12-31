#!/bin/sh

# shellcheck disable=SC2086 # Double quote to prevent globbing and word splitting ($WOLFSSL_LIBS).

set -x -e

WOLFSSL_GIT=https://github.com/wolfSSL/wolfssl
WOLFSSL_INCS="-I./wolfssl"
WOLFSSL_LIBS="-L./wolfssl/src/.libs -lwolfssl -lm"

TLS_SERVER=tls_server
TLS_CLIENT_12=tls_client_12
TLS_CLIENT_13=tls_client_13

TLS_SERVER_SRC=tls_server.c
TLS_CLIENT_SRC=tls_client.c

if [ "$1" = clean ]; then
    /bin/rm -rf wolfssl \
                $TLS_SERVER \
                $TLS_CLIENT_12 \
                $TLS_CLIENT_13
    exit
fi

if [ ! -d ./wolfssl ]; then
    git clone $WOLFSSL_GIT
    cd wolfssl
    ./autogen.sh
    cd -
fi

build_wolfssl()
{
    if [ "$1" -eq 1 ]; then
        TLS12="--enable-tlsv12"
    else
        TLS12="--disable-tlsv12"
    fi

    if [ "$2" -eq 1 ]; then
        TLS13="--enable-tls13"
    else
        TLS13="--disable-tls13"
    fi

    cd wolfssl
    if [ -f Makefile ]; then
        make distclean
    fi
    ./configure --enable-atomicuser \
                --disable-examples \
                --disable-oldtls \
                $TLS12 \
                $TLS13 \
                --enable-shared=no \
                --enable-static=yes
    make
    cd -
}

build_server()
{
    build_wolfssl 1 1
    gcc $WOLFSSL_INCS $TLS_SERVER_SRC $WOLFSSL_LIBS -o $TLS_SERVER
}

build_client_12()
{
    build_wolfssl 1 0
    gcc $WOLFSSL_INCS $TLS_CLIENT_SRC $WOLFSSL_LIBS -o $TLS_CLIENT_12
}

build_client_13()
{
    build_wolfssl 0 1
    gcc $WOLFSSL_INCS $TLS_CLIENT_SRC $WOLFSSL_LIBS -o $TLS_CLIENT_13
}

if [ "$1" = server ]; then
    build_server
elif [ "$1" = client_12 ]; then
    build_client_12
elif [ "$1" = client_13 ]; then
    build_client_13
elif [ "$1" = clients ]; then
    build_client_12
    build_client_13
else
    build_server
    build_client_12
    build_client_13
fi


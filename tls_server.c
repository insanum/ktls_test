
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

#define WC_NO_HARDEN
#include <wolfssl/ssl.h>

#define SERVER_PORT       4433
#define SERVER_CERT_FILE  "certs/server-cert.pem"
#define SERVER_KEY_FILE   "certs/server-key.pem"

int bufsize = 32768;
bool tcp_cork = false;
bool ktls_tx = false;
bool ktls_rx = false;
int server_port = SERVER_PORT;
int tls_version = 0;

static int create_server(int port)
{
	int sockfd, rc = -1, reuse = 1;
	struct sockaddr_in addr;

	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("ERROR: failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
			sizeof(int));
	if (rc < 0) {
		printf("ERROR: failed to set SO_REUSEADDR\n");
		goto end_sock;
	}

	rc = bind(sockfd, (const struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) {
		printf("ERROR: failed to bind\n");
		goto end_sock;
	}

	rc = listen(sockfd, 10);
	if (rc < 0) {
		printf("ERROR: failed to listen\n");
		goto end_sock;
	}

	return sockfd;

end_sock:
	close(sockfd);
	return -1;
}

int config_ktls(int sockfd, WOLFSSL *ssl)
{
	struct tls_crypto_info *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 crypto_128;
	struct tls12_crypto_info_aes_gcm_256 crypto_256;
	const unsigned char *key, *iv;
	int key_size, iv_size, crypto_size;
	unsigned long seq;

	if (!ktls_tx && !ktls_rx)
		return 0;

	if ((wolfSSL_GetCipherType(ssl) != WOLFSSL_AEAD_TYPE) ||
	    (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes_gcm)) {
		printf("ERROR: cipher type is not AES-GCM\n");
		return -1;
	}

	key_size = wolfSSL_GetKeySize(ssl);
	iv_size = wolfSSL_GetIVSize(ssl);

	if ((key_size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) &&
	    (key_size != TLS_CIPHER_AES_GCM_256_KEY_SIZE)) {
		printf("ERROR: invalid AES key size %d\n", key_size);
		return -1;
	}

	if (setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
		printf("ERROR: failed to set TCP_ULP\n");
		return -1;
	}

	memset(&crypto_128, 0, sizeof(crypto_128));
	memset(&crypto_256, 0, sizeof(crypto_256));

	if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
		crypto_info = &crypto_128.info;
		crypto_size = sizeof(crypto_128);
	} else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
		crypto_info = &crypto_256.info;
		crypto_size = sizeof(crypto_256);
	}

	crypto_info->version =
		(tls_version == WOLFSSL_TLSV1_2)
			? TLS_1_2_VERSION
			: TLS_1_3_VERSION;
	crypto_info->cipher_type =
		(key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE)
			? TLS_CIPHER_AES_GCM_128
			: TLS_CIPHER_AES_GCM_256;

	if (ktls_tx) {
		key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
			? wolfSSL_GetClientWriteKey(ssl)
			: wolfSSL_GetServerWriteKey(ssl);

		iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
			? wolfSSL_GetClientWriteIV(ssl)
			: wolfSSL_GetServerWriteIV(ssl);

		wolfSSL_GetSequenceNumber(ssl, &seq);
		seq = htobe64(seq);

		if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
			memcpy(crypto_128.key, key, key_size);
			memcpy(crypto_128.salt, iv, iv_size);
			memset(crypto_128.iv, 0, sizeof(crypto_128.iv));
			memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
		} else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
			memcpy(crypto_256.key, key, key_size);
			memcpy(crypto_256.salt, iv, iv_size);
			memset(crypto_256.iv, 0, sizeof(crypto_256.iv));
			memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
		}

		if (setsockopt(sockfd, SOL_TLS, TLS_TX, crypto_info,
			       crypto_size) < 0) {
			printf("ERROR: failed to set TLS_TX\n");
			return -1;
		}
	}

	if (ktls_rx) {
		key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
			? wolfSSL_GetServerWriteKey(ssl)
			: wolfSSL_GetClientWriteKey(ssl);
		iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
			? wolfSSL_GetServerWriteIV(ssl)
			: wolfSSL_GetClientWriteIV(ssl);

		wolfSSL_GetPeerSequenceNumber(ssl, &seq);
		seq = htobe64(seq);

		if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
			memcpy(crypto_128.key, key, key_size);
			memcpy(crypto_128.salt, iv, iv_size);
			memset(crypto_128.iv, 0, sizeof(crypto_128.iv));
			memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
		} else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
			memcpy(crypto_256.key, key, key_size);
			memcpy(crypto_256.salt, iv, iv_size);
			memset(crypto_256.iv, 0, sizeof(crypto_256.iv));
			memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
		}

		if (setsockopt(sockfd, SOL_TLS, TLS_RX, crypto_info,
			       crypto_size) < 0) {
			printf("ERROR: failed to set TLS_RX\n");
			return -1;
		}
	}

	return 0;
}

static void servelet(int client, WOLFSSL *ssl)
{
	char *buf;
	int bytes;
	int rc = 0;

	int err = 0;

	rc = wolfSSL_accept(ssl);
	if (rc != WOLFSSL_SUCCESS) {
		printf("ERROR: SSL accept error %d\n",
		       wolfSSL_get_error(ssl, 0));
		return;
	}

	printf("Connected to client: %s %s\n", wolfSSL_get_version(ssl),
	       wolfSSL_get_cipher(ssl));
	tls_version = wolfSSL_GetVersion(ssl);

	if (config_ktls(client, ssl) < 0) {
		printf("ERROR: failed to configure KTLS\n");
		goto end_shutdown;
	}

	if (tcp_cork) {
		int state = 1;
		setsockopt(client, IPPROTO_TCP, TCP_CORK, &state,
			   sizeof(state));
	}

	buf = malloc(bufsize);
	if (!buf) {
		printf("ERROR: failed to alloc buffer\n");
		goto end_shutdown;
	}

	while (1) {
		if (ktls_rx)
			bytes = recv(client, buf, bufsize, 0);
		else
			bytes = wolfSSL_read(ssl, buf, bufsize);
		if (bytes <= 0) {
			printf("ERROR: read error %d\n",
			       wolfSSL_get_error(ssl, 0));
			break;
		}

		printf("%d bytes received\n", bytes);

		printf("sending back %d bytes\n", bytes);

		if (ktls_tx)
			bytes = send(client, buf, bytes, 0);
		else
			bytes = wolfSSL_write(ssl, buf, bytes);
		if (bytes <= 0) {
			printf("ERROR: write error %d\n",
			       wolfSSL_get_error(ssl, 0));
			break;
		}
	}

	free(buf);
end_shutdown:
	wolfSSL_shutdown(ssl);
}

static void echoserver(void)
{
	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;
	int sockfd;
	int rc;

	sockfd = create_server(server_port);
	if (sockfd < 0)
		return;

	method = wolfSSLv23_server_method();
	ctx    = wolfSSL_CTX_new(method);

	if (wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE,
					     WOLFSSL_FILETYPE_PEM) !=
	    WOLFSSL_SUCCESS) {
		printf("ERROR: can't load server cert file\n");
		return;
	}

	if (wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE,
					    WOLFSSL_FILETYPE_PEM) !=
	    WOLFSSL_SUCCESS) {
		printf("ERROR: can't load server key file\n");
		return;
	}

	while (true) {
		WOLFSSL* ssl;
		struct sockaddr_in client_addr;
		int client_addr_len = sizeof(client_addr);
		int client;

		client = accept(sockfd, (struct sockaddr *)&client_addr,
				&client_addr_len);
		if (client < 0) {
			printf("ERROR: TCP accept failed\n");
			break;
		}

		ssl = wolfSSL_new(ctx);
		if (ssl == NULL) {
			printf("ERROR: SSL_new failed\n");
			close(client);
			break;
		}

		rc = wolfSSL_set_cipher_list(ssl,
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" ":"
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" ":"
				"TLS13-AES128-GCM-SHA256" ":"
				"TLS13-AES256-GCM-SHA384");
		if (rc != WOLFSSL_SUCCESS) {
			printf("ERROR: SSL set cipher error %d\n",
			       wolfSSL_get_error(ssl, 0));
			wolfSSL_free(ssl);
			close(client);
			break;
		}

		wolfSSL_set_fd(ssl, client);

		servelet(client, ssl);

		wolfSSL_free(ssl);
		close(client);
	}

	close(sockfd);
	wolfSSL_CTX_free(ctx);
}

static void usage(char *cmd)
{
	printf("Usage: %s [ -t ] [ -b <size> ]\n", cmd);
	printf("  -h         this usage info\n");
	printf("  -t         enable TCP cork (default off)\n");
	printf("  -k <dir>   KTLS direction (tx|rx|all|none) (default none)\n");
	printf("  -b <size>  send buffer size (default 32768)\n");
	printf("  -p <port>  port to bind to (default 4433)\n");
}

int main(int argc, char *argv[])
{
	int option;

	while ((option = getopt(argc, argv, "htk:b:p:")) != -1) {
		switch (option) {
		case 't':
			tcp_cork = true;
			break;
		case 'k':
			if (strcmp(optarg, "tx") == 0) {
				ktls_tx = true;
			} else if (strcmp(optarg, "rx") == 0) {
				ktls_rx = true;
			} else if (strcmp(optarg, "all") == 0) {
				ktls_tx = true;
				ktls_rx = true;
			} else if (strcmp(optarg, "none") != 0) {
				printf("ERROR: invalid ktls direction\n");
				usage(argv[0]);
				exit(-1);
			}
			break;
		case 'b':
			bufsize = atoi(optarg);
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		case '?':
		default:
			printf("Error: invalid argument\n");
			usage(argv[0]);
			exit(-1);
		}
	}

	printf("Starting server on port %d\n", server_port);

	wolfSSL_Init();
	echoserver();
	wolfSSL_Cleanup();

	return 0;
}


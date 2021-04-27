
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

#define WC_NO_HARDEN
#include <wolfssl/ssl.h>

#define SERVER_PORT     4433
#define SERVER_CA_FILE  "certs/ca-cert.pem"

bool quiet = false;
bool send_alert = false;
bool random_bufsize = false;
int bufsize = 32768;
int generate_data = 0;
bool tcp_cork = false;
bool send_all = false;
bool ktls_tx = false;
bool ktls_rx = false;
int server_port = SERVER_PORT;
char *server_ip = NULL;
int tls_version = 0;

enum {
	AES_128,
	AES_256
} aes = AES_128;

static int b_rand(int max)
{
	int b = (rand() % max);
	return (b == 0) ? max : b;
}

static int create_socket(char *server_ip, int port)
{
	int sockfd;
	struct sockaddr_in addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("ERROR: failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(server_ip);

	if (connect(sockfd, (struct sockaddr *)&addr,
		    sizeof(struct sockaddr_in)) == -1) {
		printf("ERROR: failed to connect\n");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

int config_ktls(int sockfd, WOLFSSL *ssl)
{
	struct tls_crypto_info *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 crypto_128;
	struct tls12_crypto_info_aes_gcm_256 crypto_256;
	const unsigned char *key, *iv;
	int key_size, iv_size, crypto_size;
	unsigned long seq;
	unsigned int rand_hi, rand_lo;

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

	rand_hi = rand();
	rand_lo = rand();

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
			if (crypto_info->version == TLS_1_2_VERSION) {
			    memcpy(crypto_128.salt, iv, 4);
			    memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
			    memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
			} else { /* TLS_1_3_VERSION */
			    memcpy(crypto_128.salt, iv, 4);
			    memcpy(crypto_128.iv, (iv + 4), 8);
			}
			memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
		} else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
			memcpy(crypto_256.key, key, key_size);
			if (crypto_info->version == TLS_1_2_VERSION) {
			    memcpy(crypto_256.salt, iv, 4);
			    memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
			    memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
			} else { /* TLS_1_3_VERSION */
			    memcpy(crypto_256.salt, iv, 4);
			    memcpy(crypto_256.iv, (iv + 4), 8);
			}
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
			if (crypto_info->version == TLS_1_2_VERSION) {
			    memcpy(crypto_128.salt, iv, 4);
			    memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
			    memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
			} else { /* TLS_1_3_VERSION */
			    memcpy(crypto_128.salt, iv, 4);
			    memcpy(crypto_128.iv, (iv + 4), 8);
			}
			memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
		} else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
			memcpy(crypto_256.key, key, key_size);
			if (crypto_info->version == TLS_1_2_VERSION) {
			    memcpy(crypto_256.salt, iv, 4);
			    memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
			    memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
			} else { /* TLS_1_3_VERSION */
			    memcpy(crypto_256.salt, iv, 4);
			    memcpy(crypto_256.iv, (iv + 4), 8);
			}
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

/* send TLS control message using record_type */
static int send_ctrl_message(int sockfd, unsigned char record_type,
			     void *data, size_t length)
{
	struct msghdr msg = { 0 };
	int cmsg_len = sizeof(record_type);
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(cmsg_len)];
	struct iovec msg_iov; /* vector of data to send from */

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_TLS;
	cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
	cmsg->cmsg_len = CMSG_LEN(cmsg_len);
	*CMSG_DATA(cmsg) = record_type;
	msg.msg_controllen = cmsg->cmsg_len;

	msg_iov.iov_base = data;
	msg_iov.iov_len = length;
	msg.msg_iov = &msg_iov;
	msg.msg_iovlen = 1;

	return sendmsg(sockfd, &msg, 0);
}

static int send_all_and_receive(int sockfd, WOLFSSL *ssl, char *buf,
				int *totsent, int *totreceived)
{
	int tmp_bufsize = bufsize;
	char buf_fill = 'a';
	int maxlen = 0;
	int len, cnt;

	socklen_t maxlen_size = sizeof(maxlen);
	getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&maxlen,
		   &maxlen_size);

	if (tcp_cork) {
		int state = 1;
		setsockopt(sockfd, IPPROTO_TCP, TCP_CORK, &state,
			   sizeof(state));
	}

	/* limit generated data to the max window size (only when corking) */
	if (generate_data > maxlen)
		generate_data = maxlen;

	for (cnt = 1; true; cnt++) {
		len = (random_bufsize) ? b_rand(tmp_bufsize) : tmp_bufsize;

		if (generate_data) {
			/*
			 * Generate data by filling the buffer with a single
			 * character. Each buffer uses the next character
			 * wrapping a-z.
			 */
			memset(buf, buf_fill, len);
			if (++buf_fill == ('z' + 1))
				buf_fill = 'a';

			printf("%4d: (generated) %d bytes\n", cnt, len);
		} else {
			/*
			 * Read data from stdin. This will be either from
			 * cmd/file data piped in or via user keyboard input.
			 */
			if ((len = read(STDIN_FILENO, buf, len)) <= 0)
				break;

			printf("%4d: (input) read %d bytes\n", cnt, len);
		}

		if (ktls_tx)
			len = send(sockfd, buf, len, 0);
		else
			len = wolfSSL_send(ssl, buf, len, 0);
		if (len <= 0) {
			printf("SSL write error %d\n",
			       wolfSSL_get_error(ssl, 0));
			break;
		}

		printf("%4d: sent %d bytes\n", cnt, len);

		*totsent += len;

		/*
		 * Don't extend past our receive window or past the requested
		 * generation size.
		 */
		if (generate_data) {
			if (*totsent >= generate_data)
				break;
			else if ((*totsent + bufsize) > generate_data)
				tmp_bufsize = (generate_data - *totsent);
		} else {
			if (*totsent >= maxlen)
				break;
			else if ((*totsent + bufsize) > maxlen)
				tmp_bufsize = (maxlen - *totsent);
		}
	}

	for (cnt = 1; (*totreceived < *totsent); cnt++) {
		if (ktls_rx)
			len = recv(sockfd, buf, bufsize, 0);
		else
			len = wolfSSL_read(ssl, buf, bufsize);
		if (len <= 0) {
			printf("ERROR: SSL read error %d\n",
			       wolfSSL_get_error(ssl, 0));
			break;
		}

		printf("%4d: received %d bytes\n", cnt, len);

		if (!quiet) {
			write(STDOUT_FILENO, buf, len);
			printf("\n");
		}

		*totreceived += len;
	}
}

static int send_receive_repeat(int sockfd, WOLFSSL *ssl, char *buf,
			       int *totsent, int *totreceived)
{
	int tmp_bufsize = bufsize;
	char buf_fill = 'a';
	int totrx;
	int len, cnt;

	for (cnt = 1; true; cnt++) {
		len = (random_bufsize) ? b_rand(tmp_bufsize) : tmp_bufsize;

		if (generate_data) {
			/*
			 * Generate data by filling the buffer with a single
			 * character. Each buffer uses the next character
			 * wrapping a-z.
			 */
			memset(buf, buf_fill, len);
			if (++buf_fill == ('z' + 1))
				buf_fill = 'a';

			printf("%4d: (generated) %d bytes\n", cnt, len);
		} else {
			/*
			 * Read data from stdin. This will be either from
			 * cmd/file data piped in or via user keyboard input.
			 */
			if ((len = read(STDIN_FILENO, buf, len)) <= 0)
				break;

			printf("%4d: (input) read %d bytes\n", cnt, len);
		}

		if (ktls_tx)
			len = send(sockfd, buf, len, 0);
		else
			len = wolfSSL_send(ssl, buf, len, 0);
		if (len <= 0) {
			printf("SSL write error %d\n",
			       wolfSSL_get_error(ssl, 0));
			break;
		}

		printf("%4d: sent %d bytes\n", cnt, len);

		*totsent += len;

		totrx = 0;
		while (totrx < len) {
			if (ktls_rx)
				len = recv(sockfd, buf, bufsize, 0);
			else
				len = wolfSSL_read(ssl, buf, bufsize);
			if (len <= 0) {
				printf("ERROR: SSL read error %d\n",
				       wolfSSL_get_error(ssl, 0));
				break;
			}

			printf("%4d: received %d bytes\n", cnt, len);

			if (!quiet) {
				write(STDOUT_FILENO, buf, len);
				printf("\n");
			}

			totrx += len;
			*totreceived += len;
		}

		/* Don't extend past the requested generation size. */
		if (generate_data) {
			if (*totsent >= generate_data)
				break;
			else if ((*totsent + bufsize) > generate_data)
				tmp_bufsize = (generate_data - *totsent);
		}
	}
}

static void echoclient(void)
{
	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl;
	char *buf;
	int sockfd;
	int totsent = 0;
	int totreceived = 0;
	int rc;

	method = wolfSSLv23_client_method();
	ctx    = wolfSSL_CTX_new(method);

	if (wolfSSL_CTX_load_verify_locations(ctx, SERVER_CA_FILE, 0) !=
	    WOLFSSL_SUCCESS) {
		printf("ERROR: can't load server CA file\n");
		goto end_ctx;
	}

	ssl = wolfSSL_new(ctx);
	if (ssl == NULL) {
		printf("ERROR: SSL_new failed\n");
		goto end_ctx;
	}

	tls_version = wolfSSL_GetVersion(ssl);

	if ((tls_version != WOLFSSL_TLSV1_2) &&
	    (tls_version != WOLFSSL_TLSV1_3)) {
		printf("ERROR: invalid TLS version %d\n", tls_version);
		goto end_ssl;
	}

	if (tls_version == WOLFSSL_TLSV1_2) {
		if (aes == AES_128)
			rc = wolfSSL_set_cipher_list(ssl,
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
		else /* (aes == AES_256) */
			rc = wolfSSL_set_cipher_list(ssl,
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
	} else { /* tls_version == WOLFSSL_TLSV1_3) */
		if (aes == AES_128)
			rc = wolfSSL_set_cipher_list(ssl,
					"TLS13-AES128-GCM-SHA256");
		else /* (aes == AES_256) */
			rc = wolfSSL_set_cipher_list(ssl,
					"TLS13-AES256-GCM-SHA384");
	}
	if (rc != WOLFSSL_SUCCESS) {
		printf("ERROR: SSL set cipher error %d\n",
		       wolfSSL_get_error(ssl, 0));
		goto end_ssl;
	}

	printf("Connecting to %s port %d...\n", server_ip, server_port);
	sockfd = create_socket(server_ip, server_port);
	if (sockfd < 0) {
		goto end_ssl;
	}

	wolfSSL_set_fd(ssl, sockfd);

	rc = wolfSSL_connect(ssl);
	if (rc != WOLFSSL_SUCCESS) {
		printf("ERROR: SSL connect error %d\n",
		       wolfSSL_get_error(ssl, 0));
		goto end_sock;
	}

	printf("Connected to server: %s %s\n", wolfSSL_get_version(ssl),
	       wolfSSL_get_cipher(ssl));

	if (config_ktls(sockfd, ssl) < 0) {
		printf("ERROR: failed to configure KTLS\n");
		goto end_sock;
	}

	buf = malloc(bufsize);
	if (!buf) {
		printf("ERROR: Failed to allocate buffer\n");
		goto end_shutdown;
	}

	printf("Buffer size is %s%d\n",
	       (random_bufsize) ? "random 1.." : "",
	       bufsize);

	if (send_alert) {
	    unsigned char alert[2];
	    alert[0] = 1; /* WARNING=1 FATAL=2 */
	    alert[1] = 10; /* unexpected message */
	    send_ctrl_message(sockfd, 21, alert, 2);
	}

	if (send_all)
		send_all_and_receive(sockfd, ssl, buf, &totsent, &totreceived);
	else
		send_receive_repeat(sockfd, ssl, buf, &totsent, &totreceived);

	printf("In total sent %d and received %d bytes\n",
	       totsent, totreceived);

	free(buf);
end_shutdown:
	wolfSSL_shutdown(ssl);
end_sock:
	close(sockfd);
end_ssl:
	wolfSSL_free(ssl);
end_ctx:
	wolfSSL_CTX_free(ctx);
}

static void usage(char *cmd)
{
	printf(
"Usage: %s [ <arguments> ] -s <ip>\n"
"  -h           this usage info\n"
"  -T           enable TCP cork (default off)\n"
"  -t           send all data then receive (default send/recv/repeat)\n"
"  -q           quiet, don't print out received data\n"
"  -c           send an alert control message first before data\n"
"  -k <dir>     KTLS direction (tx|rx|all|none) (default none)\n"
"  -a <aes>     AES key size (128|256) (default 128)\n"
"  -b <size>    send buffer (record) size (default 32768)\n"
"  -r <max>     use random send buffer (record) sizes (0..<max>)\n"
"  -g <length>  generate 'length' bytes (default stdin)\n"
"  -p <port>    server port to connect to (default 4433)\n"
"  -s <ip>      server IP to connect to\n",
cmd);
}

int main(int argc, char *argv[])
{
	int option;
	time_t t;

	srand((unsigned int)time(&t));

	while ((option = getopt(argc, argv, "hTtqck:a:b:r:g:p:s:")) != -1) {
		switch (option) {
		case 'T':
			send_all = true;
			tcp_cork = true;
			break;
		case 't':
			send_all = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'c':
			send_alert = true;
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
		case 'a':
			if (strcmp(optarg, "128") == 0) {
				aes = AES_128;
			} else if (strcmp(optarg, "256") == 0) {
				aes = AES_256;
			} else {
				printf("ERROR: invalid AES key size\n");
				usage(argv[0]);
				exit(-1);
			}
			break;
		case 'b':
			bufsize = atoi(optarg);
			break;
		case 'r':
			random_bufsize = true;
			bufsize = atoi(optarg);
			break;
		case 'g':
			generate_data = atoi(optarg);
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 's':
			server_ip = optarg;
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

	if (server_ip == NULL) {
		printf("Error: must specify the server IP\n");
		usage(argv[0]);
		exit(-1);
	}

	wolfSSL_Init();
	echoclient();
	wolfSSL_Cleanup();

	return 0;
}


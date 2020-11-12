/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <net/socket.h>
#include <modem/bsdlib.h>
#include <net/tls_credentials.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_key_mgmt.h>
#include <cJSON.h>
#include <net/mqtt.h>

#define HTTPS_PORT 8036
#define REWRITE_EXISTING_CERT false

#define HTTP_HEAD                                                               \
	"POST /v1/provisioning/aws/iot/bootstrap HTTP/1.1\r\n"                      \
	"Host: krypton.soracom.io:8036\r\n"                                         \
	"Content-Length: 47\r\n"													\
	"Content-Type: application/json\r\n\r\n"									\
	"{\"requestParameters\":{\"skipCertificates\":true}}"

#define CERT_HEAD_BEGIN "POST /v1/provisioning/aws/iot/certificates/"

#define CERT_HEAD_END															\
	" HTTP/1.1\r\n"                      										\
	"Host: krypton.soracom.io:8036\r\n"                                         \
	"Content-Type: application/json\r\n\r\n"

#define ROOT_CA_HTTP_HEAD                                                       \
	"POST /v1/provisioning/aws/iot/ca_certificate HTTP/1.1\r\n"                 \
	"Host: krypton.soracom.io:8036\r\n"                                         \
	"Content-Type: application/json\r\n\r\n"

#define ROOT_CA_HTTP_HEAD_LEN (sizeof(ROOT_CA_HTTP_HEAD) - 1)

#define HTTP_HDR_END "\r\n\r\n"

#define RECV_BUF_SIZE 4096
#define SEND_BUF_SIZE 2048
#define TLS_SEC_TAG 42

static size_t http_head_len = (sizeof(HTTP_HEAD) - 1);
static char send_buf[SEND_BUF_SIZE] = HTTP_HEAD;


/* Buffers for MQTT client. */
static u8_t rx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static u8_t tx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static u8_t payload_buf[CONFIG_MQTT_PAYLOAD_BUFFER_SIZE];

//static sec_tag_t sec_tag_list[] = { CONFIG_SEC_TAG };

/* The mqtt client struct */
static struct mqtt_client client;

/* MQTT Broker details. */
static struct sockaddr_storage broker;

/* MQTT Client ID. */
static char *mqtt_client_id;

/* MQTT Client ID. */
static char *mqtt_host;

/* Connected flag */
static bool connected;

/* File descriptor */
static struct pollfd fds;

/* Certificate for `krypton.soracom.io` */
static const char cert[] = {
	#include "../cert/Soracom-Krypton-Root-CA"
};

BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");


/* Initialize AT communications */
int at_comms_init(void)
{
	int err;

	err = at_cmd_init();
	if (err) {
		printk("Failed to initialize AT commands, err %d\n", err);
		return err;
	}

	err = at_notif_init();
	if (err) {
		printk("Failed to initialize AT notifications, err %d\n", err);
		return err;
	}

	return 0;
}

/* Provision certificate to modem */
int krypton_cert_provision(void)
{
	int err;
	bool exists;
	u8_t unused;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    &exists, &unused);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and reprovision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n",
			       err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	return 0;
}

int http_request(char ** output)
{
	int err = 0;
	int fd;
	char *p;
	char recv_buf[RECV_BUF_SIZE];
	int bytes;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	err = getaddrinfo("krypton.soracom.io", NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return err;
	}

	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", "krypton.soracom.io");
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &send_buf[off], http_head_len - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < http_head_len);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		bytes = recv(fd, &recv_buf[off], RECV_BUF_SIZE - off, 0);
		//printk("bytes: %d\n", bytes);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);

	/* Print HTTP response */
	p = strstr(recv_buf, HTTP_HDR_END);
	if (p) {
		recv_buf[off + 1] = '\0';
		off = p - recv_buf;
	} else
	{
		printk("Krypton did not return a response\n");
		err = -1;
		goto clean_up;
	}
	*output = recv_buf + off;

	printk("Finished downloading certificate.\n");

clean_up:
	freeaddrinfo(res);
	(void)close(fd);
	return err;
}

int bootstrap_aws_certs() 
{
	int err;
	cJSON *json;
	char *private_key;
	char *public_cert;
	char *root_ca;
	k_timeout_t delay = {60000};

	printk("Downloading certificates from Krypton.\n");
	
	printk("Requesting private key...\n");

	err = http_request(&private_key);
	if (err) {
		printk("Request for Krypton private key failed\n");
		return err;
	}

	json = cJSON_Parse(private_key);
	private_key = cJSON_GetObjectItemCaseSensitive(json, "privateKey")->valuestring;

	// Store MQTT settings returned from Krypton to be used for the MQTT connection
	mqtt_client_id = cJSON_GetObjectItemCaseSensitive(json, "clientId")->valuestring;
	mqtt_host = cJSON_GetObjectItemCaseSensitive(json, "host")->valuestring;

	// Use cert key from first Krypton request to download cert
	printk("Requesting public certificate...\n");
	const cJSON *certId = cJSON_GetObjectItemCaseSensitive(json, "certificateId");
	strcpy(send_buf, CERT_HEAD_BEGIN);
	strcat(send_buf, certId->valuestring);
	strcat(send_buf, CERT_HEAD_END);

	http_head_len = strlen(send_buf);

	err = http_request(&public_cert);
	if (err) {
		printk("Request for Krypton public certificate failed\n");
		return err;
	}

	json = cJSON_Parse(public_cert);
	public_cert = cJSON_GetObjectItemCaseSensitive(json, "certificate")->valuestring;

	printk("Requesting Root CA certificate...\n");

	strcpy(send_buf, ROOT_CA_HTTP_HEAD);
	http_head_len = (sizeof(ROOT_CA_HTTP_HEAD)-1);

	err = http_request(&root_ca);
	if (err) {
		printk("Request for Krypton public certificate failed\n");
		return err;
	}

	json = cJSON_Parse(root_ca);
	root_ca = cJSON_GetObjectItemCaseSensitive(json, "rootCaCertificate")->valuestring;

	// Turn off modem to provision certificates
	printk("Turning modem to offline\n");

	err = lte_lc_offline();
	if (err) {
		printk("Failed to disconnect from the LTE network, err %d\n", err);
		goto clean_up;
	}
	k_sleep(delay);

	printk("Storing private key...\n");
	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(CONFIG_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
				private_key, strlen(private_key));
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		goto clean_up;
	}

	printk("Storing public key...\n");
	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(CONFIG_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT,
				public_cert, strlen(public_cert));
	if (err) {
		printk("Failed to provision public certificate, err %d\n", err);
		goto clean_up;
	}

	printk("Storing Root CA...\n");
	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(CONFIG_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				root_ca, strlen(root_ca));
	if (err) {
		printk("Failed to provision root CA certificate, err %d\n", err);
		goto clean_up;
	}
	
	/* At this point, you could alternatively reboot the device to free up used memory. */
	printk("Credentials Stored. Bringing modem online.\n");

	err = lte_lc_normal();
	if (err) {
		printk("Failed to connect to the LTE network, err %d\n", err);
		goto clean_up;
	}
	printk("OK\n");
	
	k_sleep(delay);

	enum lte_lc_nw_reg_status status;
	lte_lc_nw_reg_status_get(&status);
	printk("Network Status: %d\n", status);

	k_sleep(delay);

	return 0;

clean_up:
	return err;
}


/**@brief Function to print strings without null-termination
 */
static void data_print(u8_t *prefix, u8_t *data, size_t len)
{
	char buf[len + 1];

	memcpy(buf, data, len);
	buf[len] = 0;
	printk("%s%s\n", prefix, buf);
}

/**@brief Function to publish data on the configured topic
 */
static int data_publish(struct mqtt_client *c, enum mqtt_qos qos,
	u8_t *data, size_t len)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = CONFIG_MQTT_PUB_TOPIC;
	param.message.topic.topic.size = strlen(CONFIG_MQTT_PUB_TOPIC);
	param.message.payload.data = data;
	param.message.payload.len = len;
	param.message_id = sys_rand32_get();
	param.dup_flag = 0;
	param.retain_flag = 0;

	data_print("Publishing: ", data, len);
	printk("to topic: %s len: %u\n",
		CONFIG_MQTT_PUB_TOPIC,
		(unsigned int)strlen(CONFIG_MQTT_PUB_TOPIC));

	return mqtt_publish(c, &param);
}

/**@brief Function to subscribe to the configured topic
 */
static int subscribe(void)
{
	struct mqtt_topic subscribe_topic = {
		.topic = {
			.utf8 = CONFIG_MQTT_SUB_TOPIC,
			.size = strlen(CONFIG_MQTT_SUB_TOPIC)
		},
		.qos = MQTT_QOS_1_AT_LEAST_ONCE
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = 1,
		.message_id = 1234
	};

	printk("Subscribing to: %s len %u\n", CONFIG_MQTT_SUB_TOPIC,
		(unsigned int)strlen(CONFIG_MQTT_SUB_TOPIC));

	return mqtt_subscribe(&client, &subscription_list);
}

/**@brief Function to read the published payload.
 */
static int publish_get_payload(struct mqtt_client *c, size_t length)
{
	u8_t *buf = payload_buf;
	u8_t *end = buf + length;

	if (length > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}

	while (buf < end) {
		int ret = mqtt_read_publish_payload(c, buf, end - buf);

		if (ret < 0) {

			if (ret != -EAGAIN) {
				return ret;
			}

			printk("mqtt_read_publish_payload: EAGAIN\n");

			
		}

		if (ret == 0) {
			return -EIO;
		}

		buf += ret;
	}

	return 0;
}

/**@brief MQTT client event handler
 */
void mqtt_evt_handler(struct mqtt_client *const c,
		      const struct mqtt_evt *evt)
{
	int err;

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			printk("MQTT connect failed %d\n", evt->result);
			break;
		}

		connected = true;
		printk("[%s:%d] MQTT client connected!\n", __func__, __LINE__);
		subscribe();
		break;

	case MQTT_EVT_DISCONNECT:
		printk("[%s:%d] MQTT client disconnected %d\n", __func__,
		       __LINE__, evt->result);

		connected = false;
		break;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *p = &evt->param.publish;

		printk("[%s:%d] MQTT PUBLISH result=%d len=%d\n", __func__,
		       __LINE__, evt->result, p->message.payload.len);
		err = publish_get_payload(c, p->message.payload.len);
		if (err >= 0) {
			data_print("Received: ", payload_buf,
				p->message.payload.len);
			/* Echo back received data */
			data_publish(&client, MQTT_QOS_1_AT_LEAST_ONCE,
				payload_buf, p->message.payload.len);
		} else {
			printk("mqtt_read_publish_payload: Failed! %d\n", err);
			printk("Disconnecting MQTT client...\n");

			err = mqtt_disconnect(c);
			if (err) {
				printk("Could not disconnect: %d\n", err);
			}
		}
	} break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) {
			printk("MQTT PUBACK error %d\n", evt->result);
			break;
		}

		printk("[%s:%d] PUBACK packet id: %u\n", __func__, __LINE__,
				evt->param.puback.message_id);
		break;

	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			printk("MQTT SUBACK error %d\n", evt->result);
			break;
		}

		printk("[%s:%d] SUBACK packet id: %u\n", __func__, __LINE__,
				evt->param.suback.message_id);
		break;

	default:
		printk("[%s:%d] default: %d\n", __func__, __LINE__,
				evt->type);
		break;
	}
}

/**@brief Resolves the configured hostname and
 * initializes the MQTT broker structure
 */
static void broker_init(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo *addr;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};

	err = getaddrinfo(mqtt_host, NULL, &hints, &result);
	while (err) {
		printk("ERROR: getaddrinfo failed %d\n", err);
		err = getaddrinfo(mqtt_host, NULL, &hints, &result);
		//return;
	}

	addr = result;
	err = -ENOENT;

	/* Look for address of the broker. */
	while (addr != NULL) {
		/* IPv4 Address. */
		if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *broker4 =
				((struct sockaddr_in *)&broker);
			char ipv4_addr[NET_IPV4_ADDR_LEN];

			broker4->sin_addr.s_addr =
				((struct sockaddr_in *)addr->ai_addr)
				->sin_addr.s_addr;
			broker4->sin_family = AF_INET;
			broker4->sin_port = htons(CONFIG_MQTT_BROKER_PORT);

			inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
				  ipv4_addr, sizeof(ipv4_addr));
			printk("IPv4 Address found %s\n", ipv4_addr);

			break;
		} else {
			printk("ai_addrlen = %u should be %u or %u\n",
				(unsigned int)addr->ai_addrlen,
				(unsigned int)sizeof(struct sockaddr_in),
				(unsigned int)sizeof(struct sockaddr_in6));
		}

		addr = addr->ai_next;
		break;
	}

	/* Free the address. */
	freeaddrinfo(result);
}

/**@brief Initialize the MQTT client structure
 */
static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	broker_init();

	/* MQTT client configuration */
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (u8_t *)mqtt_client_id;
	client->client_id.size = strlen(mqtt_client_id);
	client->password = NULL;
	client->user_name = NULL;
	client->protocol_version = MQTT_VERSION_3_1_1;

	/* MQTT buffers configuration */
	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);
	client->transport.type = MQTT_TRANSPORT_SECURE;

	struct mqtt_sec_config *tls_config = &client->transport.tls.config;

	static sec_tag_t sec_tag_list[] = { CONFIG_SEC_TAG };
    
    tls_config->peer_verify = CONFIG_PEER_VERIFY;
    tls_config->cipher_count = 0;
    tls_config->cipher_list = NULL;
    tls_config->sec_tag_count = ARRAY_SIZE(sec_tag_list);
    tls_config->sec_tag_list = sec_tag_list;
    tls_config->hostname = mqtt_host;

}

/**@brief Initialize the file descriptor structure used by poll.
 */
static int fds_init(struct mqtt_client *c)
{
	if (c->transport.type == MQTT_TRANSPORT_NON_SECURE) {
		fds.fd = c->transport.tcp.sock;
	} else {
#if defined(CONFIG_MQTT_LIB_TLS)
		fds.fd = c->transport.tls.sock;
#else
		return -ENOTSUP;
#endif
	}

	fds.events = POLLIN;

	return 0;
}

void main(void)
{
	int err;
	
	printk("Soracom Krypton client sample started\n\r");

	err = bsdlib_init();
	if (err) {
		printk("Failed to initialize bsdlib!");
		return;
	}

	/* Initialize AT comms in order to provision the certificate */
	err = at_comms_init();
	if (err) {
		return;
	}

	/* Provision krypton ssl certificates before connecting to the LTE network */
	err = krypton_cert_provision();
	if (err) {
		return;
	}

	printk("Waiting for network.. ");
	err = lte_lc_init_and_connect();
	if (err) {
		printk("Failed to connect to the LTE network, err %d\n", err);
		return;
	}
	printk("OK\n");
	
	/* Proviison X.509 Certs from Krypton */
	bool exists;
	u8_t unused;

	err = modem_key_mgmt_exists(CONFIG_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
				&exists, &unused);
	if (err) {
		printk("Failed to check if certificates exist, err %d\n", err);
		return;
	} 

	if (!REWRITE_EXISTING_CERT && exists) {
		printk("Krypton certs already exist, skipping provisioning and continuing on.\n");
	} else {
		err = bootstrap_aws_certs();
		if (err) {
			printk("Failed to provision Krypton Certs, err %d\n", err);
			return;
		} 
	}
 	
	/* Use stored certs to make AWS IoT Request */ 
	printk("Using certs to connect to AWS IoT using MQTT\n");
	client_init(&client);

	err = mqtt_connect(&client);
	if (err != 0) {
		printk("ERROR: mqtt_connect %d\n", err);
		return;
	}

	err = fds_init(&client);
	if (err != 0) {
		printk("ERROR: fds_init %d\n", err);
		return;
	}

	while (1) {
		err = poll(&fds, 1, mqtt_keepalive_time_left(&client));
		if (err < 0) {
			printk("ERROR: poll %d\n", errno);
			break;
		}

		err = mqtt_live(&client);
		if ((err != 0) && (err != -EAGAIN)) {
			printk("ERROR: mqtt_live %d\n", err);
			break;
		}

		if ((fds.revents & POLLIN) == POLLIN) {
			err = mqtt_input(&client);
			if (err != 0) {
				printk("ERROR: mqtt_input %d\n", err);
				break;
			}
		}

		if ((fds.revents & POLLERR) == POLLERR) {
			printk("POLLERR\n");
			break;
		}

		if ((fds.revents & POLLNVAL) == POLLNVAL) {
			printk("POLLNVAL\n");
			break;
		}
	}

	printk("Disconnecting MQTT client...\n");

	err = mqtt_disconnect(&client);
	if (err) {
		printk("Could not disconnect MQTT client. Error: %d\n", err);
	}


	printk("Finished, closing socket.\n");

}

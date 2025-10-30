#include <stdint.h>

#define SERVER_SCRIPT "server.sh"
#define ETH_LEN	1518

struct __attribute__((__packed__)) eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct __attribute__((__packed__)) ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	uint16_t len;			/* total length */
	uint16_t id;			/* identification */
	uint16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct __attribute__((__packed__)) eth_ip_s {
	struct eth_hdr ethernet;
	struct ip_hdr ip;
};

int tun_alloc(char *dev, int flags);
int tun_read(int tun_fd, char *buffer, int length);
int tun_write(int tun_fd, char *buffer, int length);
void run_tunnel(int server, int argc, char *argv[]);

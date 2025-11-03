#define SERVER_SCRIPT "server.sh"
#define ETH_LEN	1518

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

int tun_alloc(char *dev, int flags);
int tun_read(int tun_fd, char *buffer, int length);
int tun_write(int tun_fd, char *buffer, int length);
void run_tunnel(int server, int argc, char *argv[]);

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <pwd.h>
#include <pthread.h>
#include <unistd.h>
#include "tunnel.h"

#define MTU 1472

static int get_default_gateway(const char *ifName, struct in_addr *gw)
{
	FILE *fp = fopen("/proc/net/route", "r");
	if (!fp)
		return -1;

	char iface[IFNAMSIZ];
	unsigned long destination, gateway;
	unsigned int flags;
	int found = -1;

	char line[256];
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%63s %lx %lx %X", iface, &destination, &gateway, &flags) < 4)
			continue;
		if (strcmp(iface, ifName) != 0)
			continue;
		if (destination != 0)
			continue;
		struct in_addr g;
		g.s_addr = htonl(gateway);
		*gw = g;
		found = 0;
		break;
	}

	fclose(fp);
	return found;
}

static int get_interface_ipv4(int sock_fd, const char *ifName, struct in_addr *addr, struct in_addr *netmask)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifName);
	if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0)
		return -1;
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifName);
	if (ioctl(sock_fd, SIOCGIFNETMASK, &ifr) < 0)
		return -1;
	*netmask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
	return 0;
}

static int send_dummy_udp(const char *ifName, struct in_addr target)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = target;
	addr.sin_port = htons(9);

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifName, strlen(ifName) + 1) < 0) {
		close(fd);
		return -1;
	}

	sendto(fd, "", 0, 0, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);
	return 0;
}

static int lookup_mac(int ioctl_fd, const char *ifName, struct in_addr target, unsigned char mac[6])
{
	struct arpreq req;
	memset(&req, 0, sizeof(req));
	struct sockaddr_in *pa = (struct sockaddr_in *)&req.arp_pa;
	pa->sin_family = AF_INET;
	pa->sin_addr = target;
	snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", ifName);

	if (ioctl(ioctl_fd, SIOCGARP, &req) < 0)
		return -1;

	memcpy(mac, req.arp_ha.sa_data, 6);
	return 0;
}

static int resolve_mac_for_ipv4(int ioctl_fd, const char *ifName, struct in_addr dest, struct in_addr iface_addr, struct in_addr netmask, int have_gateway, struct in_addr gateway, unsigned char mac[6])
{
	struct in_addr target = dest;
	int same_subnet = ((dest.s_addr & netmask.s_addr) == (iface_addr.s_addr & netmask.s_addr));
	if (!same_subnet) {
		if (!have_gateway)
			return -1;
		target = gateway;
	}

	if (lookup_mac(ioctl_fd, ifName, target, mac) == 0)
		return 0;

	send_dummy_udp(ifName, target);
	if (lookup_mac(ioctl_fd, ifName, target, mac) == 0)
		return 0;

	return -1;
}


int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int tun_fd, err;
	char *clonedev = "/dev/net/tun";
	printf("[DEBUG] Allocating tunnel\n");

	tun_fd = open(clonedev, O_RDWR);

	if(tun_fd == -1) {
		perror("Unable to open clone device");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
	}

	if ((err=ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
		int saved_errno = errno;
		close(tun_fd);
		errno = saved_errno;
		fprintf(stderr, "Error returned by ioctl(TUNSETIFF): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("[DEBUG] Created tunnel %s\n", dev);

	return tun_fd;
}

int tun_read(int tun_fd, char *buffer, int length)
{
	int bytes_read;
	bytes_read = read(tun_fd, buffer, length);

	if (bytes_read == -1) {
		perror("tun_read: read");
		return -1;
	} else {
		return bytes_read;
	}
}

int tun_write(int tun_fd, char *buffer, int length)
{
	int bytes_written;
	bytes_written = write(tun_fd, buffer, length);

	if (bytes_written == -1) {
		if (errno == EIO || errno == ENETDOWN) {
			return -1;
		}
		perror("tun_write: write");
		return -1;
	} else {
		return bytes_written;
	}
}

void configure_network(int server, char *client_script)
{
	int pid, status;
	char path[100];
	char *const args[] = {path, NULL};

	if (server) {
		size_t script_len = strlen(SERVER_SCRIPT);
		if (script_len >= sizeof(path)){
			perror("Server script path is too long\n");
			exit(EXIT_FAILURE);
		}
		memcpy(path, SERVER_SCRIPT, script_len + 1);
	} else {
		size_t script_len = strlen(client_script);
		if (script_len >= sizeof(path)){
			perror("Client script path is too long\n");
			exit(EXIT_FAILURE);
		}
		memcpy(path, client_script, script_len + 1);
	}

	pid = fork();

	if (pid == -1) {
		perror("Unable to fork\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		exit(execv(path, args));
	} else {
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) == 0) {
			printf("[DEBUG] Script ran successfully\n");
		} else {
			printf("[DEBUG] Error in running script\n");
		}
	}
}

void print_hexdump(char *str, int len)
{
	for (int i = 0; i < len; i++) {
		if (i % 16 == 0 && i != 0) printf("\n");
		printf("%02x ", (unsigned char)str[i]);
	}
	if (len > 0) printf("\n");
}

void run_tunnel(int server, int argc, char *argv[])
{
	unsigned char this_mac[6];
	unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char resolved_mac[6];

	char buf[ETH_LEN];
	struct eth_hdr *eth_hdr = (struct eth_hdr *)&buf;
	char *payload = (char *)&buf + sizeof(struct eth_hdr);

	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sock_fd, tun_fd, size;
	int ioctl_fd = -1;
	struct in_addr iface_addr = {0};
	struct in_addr iface_netmask = {0};
	struct in_addr gateway_addr = {0};
	int have_iface_addr = 0;
	int have_gateway = 0;

	fd_set fs;

	tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);

	printf("[DEBUG] Starting tunnel - Mode: %s\n", server ? "server" : "client");
	printf("[DEBUG] Opening socket\n");

	/* Get interface name */
	if (argc >= 3) {
		strcpy(ifName, argv[1]);
	} else {
		perror("Error configuring interface\n");
		exit(1);
	}

	/* Open RAW socket */
	if ((sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl_fd == -1)
		perror("socket(AF_INET)");

	/* Set interface to promiscuous mode */
	snprintf(ifopts.ifr_name, sizeof(ifopts.ifr_name), "%s", ifName);
	ioctl(sock_fd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sock_fd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	snprintf(if_idx.ifr_name, sizeof(if_idx.ifr_name), "%s", ifName);
	if (ioctl(sock_fd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	snprintf(if_mac.ifr_name, sizeof(if_mac.ifr_name), "%s", ifName);
	if (ioctl(sock_fd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	if (get_interface_ipv4(ioctl_fd >= 0 ? ioctl_fd : sock_fd, ifName, &iface_addr, &iface_netmask) == 0)
		have_iface_addr = 1;
	if (get_default_gateway(ifName, &gateway_addr) == 0)
		have_gateway = 1;

	if (server)
		configure_network(server, 0);
	else
		configure_network(server, argv[3]);

	while (1) {
		FD_ZERO(&fs);
		FD_SET(tun_fd, &fs);
		FD_SET(sock_fd, &fs);

		int max_fd = tun_fd > sock_fd ? tun_fd : sock_fd;
		int ready = select(max_fd + 1, &fs, NULL, NULL, NULL);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			perror("select");
			break;
		}
		if (ready == 0)
			continue;

		if (FD_ISSET(tun_fd, &fs)) {
			printf("[DEBUG] Read tun device\n");
			memset(&buf, 0, sizeof(buf));
			
			/* Fill the payload with tunnel data */
			size = tun_read(tun_fd, payload, MTU);
			if (size == -1)
				continue;
			print_hexdump(payload, size);

			uint16_t ether_type = ETH_P_IP;
			if (size > 0) {
				uint8_t version = ((uint8_t)payload[0]) >> 4;
				if (version == 6) {
					ether_type = ETH_P_IPV6;
				}
			}

			/* Fill the Ethernet frame header */
			int have_dest_mac = 0;
			if (ether_type == ETH_P_IP && size >= 20 && have_iface_addr) {
				struct in_addr dest_ip;
				memcpy(&dest_ip, payload + 16, sizeof(dest_ip));
				int resolver_fd = (ioctl_fd >= 0) ? ioctl_fd : sock_fd;
				if (resolve_mac_for_ipv4(resolver_fd, ifName, dest_ip, iface_addr, iface_netmask, have_gateway, gateway_addr, resolved_mac) == 0) {
					memcpy(eth_hdr->dst_addr, resolved_mac, 6);
					have_dest_mac = 1;
				}
			}
			if (!have_dest_mac) {
				memcpy(eth_hdr->dst_addr, broadcast_mac, 6);
			}
			memcpy(eth_hdr->src_addr, this_mac, 6);
			eth_hdr->eth_type = htons(ether_type);
			socket_address.sll_protocol = htons(ether_type);

			/* Send the raw socket packet */
			memcpy(socket_address.sll_addr, eth_hdr->dst_addr, 6);
			if (sendto(sock_fd, buf, size + sizeof(struct eth_hdr), 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				printf("Send failed\n");

			printf("[DEBUG] Sent packet\n");
		}

		if (FD_ISSET(sock_fd, &fs)) {
			/* Get ethernet data */
			size = recvfrom(sock_fd, buf, ETH_LEN, 0, NULL, NULL);
			if (size <= (int)sizeof(struct eth_hdr))
				continue;
			if (memcmp(eth_hdr->src_addr, this_mac, 6) == 0)
				continue;

			uint16_t recv_eth_type = ntohs(eth_hdr->eth_type);
			char *recv_payload = (char *)&buf + sizeof(struct eth_hdr);

			if (recv_eth_type == ETH_P_IP || recv_eth_type == ETH_P_IPV6) {
				if (tun_write(tun_fd, recv_payload, size - sizeof(struct eth_hdr)) == -1)
					continue;
			}
		}
	}

	close(tun_fd);
	close(sock_fd);
	if (ioctl_fd >= 0)
		close(ioctl_fd);
}

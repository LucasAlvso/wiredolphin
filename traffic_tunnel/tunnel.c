#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <pwd.h>
#include <pthread.h>
#include <unistd.h>
#include "tunnel.h"

#define MTU 1472
#define DEFAULT_ROUTE   "0.0.0.0"


int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int tun_fd, err;
	char *clonedev = "/dev/net/tun";
	printf("[DEBUG] Allocating tunnel\n");

	tun_fd = open(clonedev, O_RDWR);

	if(tun_fd == -1) {
		perror("Unable to open clone device\n");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	}

	if ((err=ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(tun_fd);
		fprintf(stderr, "Error returned by ioctl(): %s\n", strerror(err));
		perror("Error in tun_alloc()\n");
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
		perror("Unable to read from tunnel\n");
		exit(EXIT_FAILURE);
	} else {
		return bytes_read;
	}
}

int tun_write(int tun_fd, char *buffer, int length)
{
	int bytes_written;
	bytes_written = write(tun_fd, buffer, length);

	if (bytes_written == -1) {
		perror("Unable to write to tunnel\n");
		exit(EXIT_FAILURE);
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
		if (sizeof(SERVER_SCRIPT) > sizeof(path)){
			perror("Server script path is too long\n");
			exit(EXIT_FAILURE);
		}
		strncpy(path, SERVER_SCRIPT, strlen(SERVER_SCRIPT) + 1);
	} else {
		if (strlen(client_script) > sizeof(path)){
			perror("Client script path is too long\n");
			exit(EXIT_FAILURE);
		}
		strncpy(path, client_script, sizeof(path));
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
		if (i % 16 == 0) printf("\n");
		printf("%02x ", (unsigned char)str[i]);
	}
	printf("\n");
}

unsigned long ipchksum(char *packet)
{
	unsigned long sum = 0;

	for (int i = 0; i < 20; i += 2)
		sum += ((unsigned long)packet[i] << 8) | (unsigned long)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
		
	return sum;
}


void run_tunnel(int server, int argc, char *argv[])
{
	/* Disable stdio buffering so logs appear in container logs immediately */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	char this_mac[6];
	char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char dst_mac[6] =	{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	/* We'll use the real interface MAC for the Ethernet source to avoid bridge anti-spoof drops */
	char src_mac[6] =	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	char buf[ETH_LEN];
	struct eth_ip_s *hdr = (struct eth_ip_s *)&buf;
	char *payload = (char *)&buf + sizeof(struct eth_ip_s);

	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sock_fd, tun_fd, size;

	/* Optional UDP encapsulation (more portable across bridges/NAT) */
	int udp_mode = 0;
	int udp_fd = -1;
	int udp_port = 5555;
	struct sockaddr_in udp_peer;      /* client -> server destination (client mode) */
	struct sockaddr_in udp_recv_addr; /* address we received from (server mode) */
	socklen_t udp_recv_len = sizeof(udp_recv_addr);

	/* Simple mapping between inner client IPv4 address and its UDP endpoint (server side) */
	struct map_entry { uint32_t ip_be; struct sockaddr_in sa; };
	struct map_entry client_map[64];
	int client_map_count = 0;

	fd_set fs;

	/* Optionally override destination MAC via env var TUN_PEER_MAC (format: aa:bb:cc:dd:ee:ff) */
	char *peer_env = getenv("TUN_PEER_MAC");
	if (peer_env && strlen(peer_env) == 17) {
		unsigned int b[6];
		if (sscanf(peer_env, "%02x:%02x:%02x:%02x:%02x:%02x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
			for (int i = 0; i < 6; i++) dst_mac[i] = (char)b[i];
			printf("[DEBUG] Using unicast peer MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				   (unsigned char)dst_mac[0], (unsigned char)dst_mac[1], (unsigned char)dst_mac[2],
				   (unsigned char)dst_mac[3], (unsigned char)dst_mac[4], (unsigned char)dst_mac[5]);
		}
	} else {
		printf("[DEBUG] Using broadcast destination (no TUN_PEER_MAC set)\n");
	}

	tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);

	printf("[DEBUG] Starting tunnel - Mode: %s\n", server ? "server" : "client");
	printf("[DEBUG] Opening socket\n");

	/* Check if we should use UDP encapsulation instead of raw Ethernet */
	char *use_udp_env = getenv("TUN_USE_UDP");
	if (use_udp_env && (strcmp(use_udp_env, "1") == 0 || strcasecmp(use_udp_env, "true") == 0)) {
		udp_mode = 1;
		char *port_env = getenv("TUN_UDP_PORT");
		if (port_env && atoi(port_env) > 0) udp_port = atoi(port_env);
		udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (udp_fd < 0) {
			perror("socket(AF_INET, SOCK_DGRAM)");
			exit(EXIT_FAILURE);
		}
		memset(&udp_peer, 0, sizeof(udp_peer));
		memset(&udp_recv_addr, 0, sizeof(udp_recv_addr));

		if (server) {
			/* Bind server UDP socket */
			struct sockaddr_in bind_addr;
			memset(&bind_addr, 0, sizeof(bind_addr));
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
			bind_addr.sin_port = htons(udp_port);
			if (bind(udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
				perror("bind UDP server");
				exit(EXIT_FAILURE);
			}
			printf("[DEBUG] UDP mode enabled (server) on port %d\n", udp_port);
		} else {
			/* Resolve peer host for client */
			char *peer_host = getenv("TUN_PEER_IP");
			if (!peer_host || strlen(peer_host) == 0) {
				fprintf(stderr, "[ERROR] UDP mode requires TUN_PEER_IP env var set to server host/ip\n");
				exit(EXIT_FAILURE);
			}
			struct addrinfo hints, *res = NULL;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET; /* IPv4 */
			hints.ai_socktype = SOCK_DGRAM;
			int rc = getaddrinfo(peer_host, NULL, &hints, &res);
			if (rc != 0 || !res) {
				fprintf(stderr, "[ERROR] getaddrinfo(%s) failed: %s\n", peer_host, gai_strerror(rc));
				exit(EXIT_FAILURE);
			}
			struct sockaddr_in *peer_in = (struct sockaddr_in *)res->ai_addr;
			udp_peer.sin_family = AF_INET;
			udp_peer.sin_addr = peer_in->sin_addr;
			udp_peer.sin_port = htons(udp_port);
			freeaddrinfo(res);
			char ipbuf[64];
			inet_ntop(AF_INET, &udp_peer.sin_addr, ipbuf, sizeof(ipbuf));
			printf("[DEBUG] UDP mode enabled (client) to %s:%d\n", ipbuf, udp_port);
		}
	}

	/* Get interface name */
	if (argc >= 3) {
		strcpy(ifName, argv[1]);
	} else {
		perror("Error configuring interface\n");
		exit(1);
	}

	/* Open RAW socket for Ethernet encapsulation (disabled if UDP mode) */
	if (!udp_mode) {
		if ((sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
			perror("socket");
			exit(EXIT_FAILURE);
		}
	} else {
		sock_fd = -1; /* not used in UDP mode */
	}

	/* Set interface to promiscuous mode (only for raw socket mode) */
	if (!udp_mode) {
		strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
		ioctl(sock_fd, SIOCGIFFLAGS, &ifopts);
		ifopts.ifr_flags |= IFF_PROMISC;
		ioctl(sock_fd, SIOCSIFFLAGS, &ifopts);
	}

	/* Get the index of the interface (raw mode) */
	if (!udp_mode) {
		memset(&if_idx, 0, sizeof(struct ifreq));
		strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(sock_fd, SIOCGIFINDEX, &if_idx) < 0)
			perror("SIOCGIFINDEX");
		memset(&socket_address, 0, sizeof(socket_address));
		socket_address.sll_family   = AF_PACKET;
		socket_address.sll_protocol = htons(ETH_P_IP);
		socket_address.sll_ifindex  = if_idx.ifr_ifindex;
		socket_address.sll_halen    = ETH_ALEN;
	}

	/* Bind the raw socket to the interface to make sure we receive frames on it */
	if (!udp_mode) {
		struct sockaddr_ll bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sll_family   = AF_PACKET;
		bind_addr.sll_protocol = htons(ETH_P_ALL);
		bind_addr.sll_ifindex  = if_idx.ifr_ifindex;
		if (bind(sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
			perror("bind(AF_PACKET) failed");
		}
	}

	/* Get the MAC address of the interface (raw mode) */
	if (!udp_mode) {
		memset(&if_mac, 0, sizeof(struct ifreq));
		strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(sock_fd, SIOCGIFHWADDR, &if_mac) < 0)
			perror("SIOCGIFHWADDR");
		memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);
		memcpy(src_mac, this_mac, 6);
	}

	if (server)
		configure_network(server, 0);
	else
		configure_network(server, argv[3]);

	while (1) {
		FD_ZERO(&fs);
		FD_SET(tun_fd, &fs);
	if (!udp_mode) FD_SET(sock_fd, &fs);
	if (udp_mode) FD_SET(udp_fd, &fs);

	int maxfd = tun_fd;
	if (!udp_mode && sock_fd > maxfd) maxfd = sock_fd;
	if (udp_mode && udp_fd > maxfd) maxfd = udp_fd;
	select(maxfd + 1, &fs, NULL, NULL, NULL);

		if (FD_ISSET(tun_fd, &fs)) {
			printf("[DEBUG] Read tun device\n");
			memset(&buf, 0, sizeof(buf));
			
			/* Fill the payload with tunnel data */
			size = tun_read(tun_fd, payload, MTU);
			if (size == -1) {
				perror("Error while reading from tun device\n");
				exit(EXIT_FAILURE);
			}
			print_hexdump(payload, size);
			if (udp_mode) {
				/* UDP encapsulation */
				if (!server) {
					int sent = sendto(udp_fd, payload, size, 0, (struct sockaddr *)&udp_peer, sizeof(udp_peer));
					if (sent < 0) perror("sendto(UDP) failed");
					else printf("[DEBUG] Sent UDP packet (%d bytes)\n", sent);
				} else {
					/* Server side: need to decide which client to send to based on inner dst IP */
					if (size >= 20 && (payload[0] >> 4) == 4) {
						/* IPv4 */
						uint32_t dst_ip_be = *(uint32_t *)(payload + 16);
						int found = -1;
						for (int i = 0; i < client_map_count; i++) {
							if (client_map[i].ip_be == dst_ip_be) { found = i; break; }
						}
						if (found >= 0) {
							int sent = sendto(udp_fd, payload, size, 0, (struct sockaddr *)&client_map[found].sa, sizeof(struct sockaddr_in));
							if (sent < 0) perror("sendto(UDP-server) failed");
							else printf("[DEBUG] Sent UDP to client %d.%d.%d.%d (%d bytes)\n",
										 payload[16], payload[17], payload[18], payload[19], sent);
						} else {
							printf("[DEBUG] No client mapping for inner dst, dropping\n");
						}
					} else {
						/* Non-IPv4 inner: drop */
					}
				}
			} else {
				/* Raw Ethernet encapsulation */
				/* Fill the Ethernet frame header */
				memcpy(hdr->ethernet.dst_addr, bcast_mac, 6);
				/* Use the actual interface MAC as Ethernet source */
				memcpy(hdr->ethernet.src_addr, src_mac, 6);
				hdr->ethernet.eth_type = htons(ETH_P_IP);

				/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
				hdr->ip.ver = 0x45;
				hdr->ip.tos = 0x00;
				hdr->ip.len = htons(size + sizeof(struct ip_hdr));
				hdr->ip.id = htons(0x00);
				hdr->ip.off = htons(0x00);
				hdr->ip.ttl = 50;
				hdr->ip.proto = 0xff;
				hdr->ip.sum = htons(0x0000);

				if (server) {
					hdr->ip.src[0] = 192; hdr->ip.src[1] = 168; hdr->ip.src[2] = 255; hdr->ip.src[3] = 1;
					hdr->ip.dst[0] = 192; hdr->ip.dst[1] = 168; hdr->ip.dst[2] = 255; hdr->ip.dst[3] = 10;
				} else {
					hdr->ip.src[0] = 192; hdr->ip.src[1] = 168; hdr->ip.src[2] = 255; hdr->ip.src[3] = 10;
					hdr->ip.dst[0] = 192; hdr->ip.dst[1] = 168; hdr->ip.dst[2] = 255; hdr->ip.dst[3] = 1;
				}

				hdr->ip.sum = htons((~ipchksum((char *)&hdr->ip) & 0xffff));

				/* Prefer unicast to configured peer if provided, else broadcast */
				if (peer_env && strlen(peer_env) == 17) {
					memcpy(hdr->ethernet.dst_addr, dst_mac, 6);
					memcpy(socket_address.sll_addr, dst_mac, 6);
				} else {
					memcpy(hdr->ethernet.dst_addr, bcast_mac, 6);
					memcpy(socket_address.sll_addr, bcast_mac, 6);
				}
				int sent = sendto(sock_fd, buf, size + sizeof(struct eth_ip_s), 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll));
				if (sent < 0) {
					perror("sendto failed");
				} else {
					printf("[DEBUG] Sent packet (%d bytes)\n", sent);
				}
			}
		}

		if (!udp_mode && FD_ISSET(sock_fd, &fs)) {
			/* Get ethernet data */
			size = recvfrom(sock_fd, buf, ETH_LEN, 0, NULL, NULL);
			if (size <= 0) continue;
			/* Ensure we at least have Ethernet + IPv4 header */
			if (size < (int)sizeof(struct eth_ip_s)) continue;
			printf("[DEBUG] Received frame: size=%d eth_type=0x%04x ip_proto=%u\n", size, ntohs(hdr->ethernet.eth_type), hdr->ip.proto);
			/* Correctly interpret ethertype; only process IPv4 */
			if (ntohs(hdr->ethernet.eth_type) != ETH_P_IP) continue;
			/* Only accept our tunnel frames marked with IP proto 0xff */
			if (hdr->ip.proto != 0xff) continue;

			/* Deliver the inner IP payload to the TUN device regardless of outer IPs */
			print_hexdump(buf, size);
			int inner_len = size - (int)sizeof(struct eth_ip_s);
			if (inner_len > 0) {
				tun_write(tun_fd, payload, inner_len);
				printf("[DEBUG] Write tun device (%d bytes)\n", inner_len);
			}
		}

		if (udp_mode && FD_ISSET(udp_fd, &fs)) {
			/* Receive UDP encapsulated payload */
			size = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&udp_recv_addr, &udp_recv_len);
			if (size <= 0) continue;
			/* Update mapping (server side) based on inner source IP */
			if (server && size >= 20 && ((buf[0] >> 4) == 4)) {
				uint32_t src_ip_be = *(uint32_t *)(buf + 12);
				int found = -1;
				for (int i = 0; i < client_map_count; i++) {
					if (client_map[i].ip_be == src_ip_be) { found = i; break; }
				}
				if (found < 0 && client_map_count < (int)(sizeof(client_map)/sizeof(client_map[0]))) {
					client_map[client_map_count].ip_be = src_ip_be;
					client_map[client_map_count].sa = udp_recv_addr;
					client_map_count++;
					printf("[DEBUG] Learned client %d.%d.%d.%d -> %s:%d\n",
						   buf[12], buf[13], buf[14], buf[15],
						   inet_ntoa(udp_recv_addr.sin_addr), ntohs(udp_recv_addr.sin_port));
				}
			}
			tun_write(tun_fd, buf, size);
			printf("[DEBUG] Write tun device (%d bytes)\n", size);
		}
	}
}

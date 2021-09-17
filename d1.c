#include "dneasy.h"
#include "tools.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

ssize_t trx(uint8_t *buf, size_t len, size_t size, const dneasy_ip *ip) {
	// open UDP socket for DNS:
	int s = socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP);
	if (s < 0) {
		// failed to open socket
		return -1;
	}

	// set socket timeout:
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 100000;
	if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
		return -5;
	}
	if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
		return -6;
	}

	struct sockaddr_storage addr_s;
	struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr_s;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &addr_s;
	struct sockaddr *addr = (struct sockaddr *) &addr_s;
	socklen_t addr_l;

	if (ip->type == DNEASY_IP4) {
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(ip->port);
		memcpy(&addr4->sin_addr, &ip->addr, 4);
		addr_l = sizeof(*addr4);
	} else if (ip->type == DNEASY_IP6) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(ip->port);
		memcpy(&addr6->sin6_addr, &ip->addr, 16);
		addr_l = sizeof(*addr6);
	} else {
		return -4;
	}

	if( sendto(s, (char*) buf, len, 0, addr, addr_l) < 0) {
		// failed to send
		close(s);
		return -2;
	}

	printf("\nReceiving answer...\n");
	ssize_t got;
	addr_l = sizeof(addr_s);
	if( (got = recvfrom(s, buf, size , 0 , addr , &addr_l)) < 0) {
		// recv failed
		close(s);
		return -3;
	}
	// success
	close(s);
	return got;
}

dneasy_ip dns_ips[16];
ssize_t dns_ip_count = 0;

int main(void) {
	dns_ip_count = dneasy_parse_server_list(dns_ips, 16, "8.8.8.8:80,9.9.9.9");
	Log("DNS-Servers: %zd\n", dns_ip_count);
	for (int i=0; i<dns_ip_count; i++) {
		Log("  %s\n", dneasy_ip_to_string(&(dns_ips[i])));
	}

	dneasy_ip ip;
	memset(&ip, 0, sizeof ip);
	uint32_t ttl=0xffffffff;
	memset(&ip, 0, sizeof(ip));
	if (dneasy_resolve_list(&ip, &ttl, "platform.lobaro.com", dns_ips, dns_ip_count, trx)) {
		Log("IP:  %s\nttl: %us\n", dneasy_ip_to_string(&ip), ttl);
	} else {
		Log("Failed\n");
	}
}

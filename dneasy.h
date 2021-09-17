#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <stdint-gcc.h>

#define DNEASY_IP4 4u
#define DNEASY_IP6 6u

typedef struct __attribute__((__packed__)) {
	uint8_t type;
	uint8_t addr[16];
	uint16_t port;
} dneasy_ip;

typedef ssize_t (*dneasy_trx_t)(uint8_t *buf, size_t len, size_t size, const dneasy_ip *ip);

/**
 * Parse IPv4 from null-terminated String (dotted notation). A port can be added optionally separated by `:`.
 * @param ip
 * @param s
 * @return `true` on success, `false` else.
 */
bool dneasy_parse_ip4(dneasy_ip *ip, const char *s);
/**
 * Parse IPv6 from null-terminated String - not implemented yet, always fails.
 * @param ip
 * @param s
 * @return
 */
//bool dneasy_parse_ip6(dneasy_ip *ip, const char *s);
/**
 * Parse IP address from null-terminated String, either (v4 or v6) with optional port (separated by `:`).
 * (ipv6 not implemented, yet)
 * @param ip
 * @param s
 * @return
 */
bool dneasy_parse_ip(dneasy_ip *ip, const char *s);

/**
 * Resolve single host using a single dns server.
 */
bool dneasy_resolve(dneasy_ip *ip, uint32_t *ttl, const char *host, const dneasy_ip *dns, dneasy_trx_t trx);

/**
 * Resolve a single host using a list of dns servers (tries servers until one request succeeds).
 */
bool dneasy_resolve_list(dneasy_ip *ip, uint32_t *ttl, const char *host, const dneasy_ip *dns_list, size_t list_size, dneasy_trx_t trx);

/**
 * Print IP to readable form in string. Uses static buffer (must not be freed, will be overwritten on subsequent calls).
 */
const char *dneasy_ip_to_string(dneasy_ip *ip);

ssize_t dneasy_parse_server_list(dneasy_ip *ips, size_t size, const char *list);

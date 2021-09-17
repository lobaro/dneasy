#include <sys/types.h>
#include <string.h>
#include "dneasy.h"
#include "tools.h"

/**
 * Names in dns messages have a variable length. The only way to get to the data behind the name
 * is skipping it. This uses the length information taken from the message, so length is untrusted
 * data. We supply a pointer to the end of the data (first byte after and of data), to make sure
 * we do not read outside of the message (so no buffer overflow).
 * This skips names as well as references to names within message (compressed format).
 * @param p Pointer to begin of the name in dns message.
 * @param end Pointer to first byte after message, used for buffer overflow avoidance.
 * @return On success: Pointer to the first byte trailing the name. On error (e.g. buffer overflow): NULL
 */
static const uint8_t *skip_name(const uint8_t *p, const uint8_t *end) {
	if (p == NULL || end == NULL || p >= end) {
		return NULL;
	}
	if (((*p) & 0xc0) == 0xc0) {
		// This is a pointer to an earlier name. These are always 2 bytes long, so just skip those
		if (p + 2 >= end) {
			return NULL;
		} else {
			return p + 2;
		}
	} else {
		// names consist of parts, each part is prefixed by its length. Name is terminated by 0 byte
		// (which would be a zero length part, which is not allowed)
		while (*p != 0x00) {
			p += (*p + 1);
			if (p >= end) {
				return NULL;
			}
		}
		// skip final zero
		p++;
		if (p >= end) {
			return NULL;
		} else {
			return p;
		}
	}
}

/**
 * Build a DNS-request message very basically. Does only exactly what we need, request IP for a single name.
 */
static ssize_t build_req(uint8_t *buf, size_t buf_len, const char *n) {
	static uint16_t id = 0xaffe;
	size_t n_len = strlen(n);
	if (n_len > 255) {
		// too long, we do not support that
		return -2;
	}
	// DNS-Header: 12 bytes
	// QNAME: n_len + 2 bytes (for additional length and final 0-length bytes)
	// QTYPE: 2 bytes
	// QCLASS: 2 bytes
	size_t needed = 12 + (n_len + 2) + 2 + 2;
	if (buf_len < needed) {
		// request too long for buffer
		return -1;
	}
	// example for "lobaro.com":
	// AF FE 01 00 00 01 00 00 00 00 00 00 06 6C 6F 62 61 72 6F 03 63 6F 6D 00 00 01 00 01
	// AF FE 01 00 00 01 00 00 00 00 00 00 06 6C 6F 62 61 72 6F 03 63 6F 6D 00 00 01 00 01


	// write HEADER
	memset(buf, 0, 12);
	buf[0] = id >> 8u;
	buf[1] = id & 0xffu;
	buf[2] = 1u;
	buf[5] = 1u;
	id++;

	uint8_t *p = buf + 12;
	uint8_t l = 0;
	for (int i = 0; i < n_len; i++) {
		if (n[i] == '.') {
			// prefix part with part's length:
			if (l < 1) {
				return -3;
			}
			if (l > 63) {
				return -4;
			}
			*(p++) = l;
			// copy part:
			memcpy(p, n + i - l, l);
			p += l;
			l = 0;
		} else {
			l++;
		}
	}
	// prefix final part with part's length:
	if (l < 1) {
		return -3;
	}
	if (l > 63) {
		return -4;
	}
	*(p++) = l;
	// copy part:
	memcpy(p, n + n_len - l, l);
	p += l;
	// final 0x00 to terminate qname
	*(p++) = 0x00;
	// qtype and qclass are statid
	*(p++) = 0u;
	*(p++) = 1u;
	*(p++) = 0u;
	*(p++) = 1u;
	return p - buf;
}

/**
 * Internal struct used to hold parsed DNS answer.
 */
typedef struct {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
	const uint8_t *rdata;
} dns_answer;

/**
 * Parse a single answer from DNS response. Uses same buffer protection as `skip_name()`.
 * Returns: Onsuccess: the number of bytes taken by the answer, so you can skip them. On failure n<0.
 */
static ssize_t parse_answer(dns_answer *a, const uint8_t *p, const uint8_t *end) {
	if (p == NULL || end == NULL || p + 10 >= end) {
		return -1;
	}
	a->type = ParseUInt16BigEndian(p);
	a->class = ParseUInt16BigEndian(p + 2);
	a->ttl = ParseUInt32BigEndian(p + 4);
	a->rdlen = ParseUInt16BigEndian(p + 8);
	if (p + 10 + a->rdlen > end) {
		return -2;
	}
	a->rdata = p + 10;
	return 10 + a->rdlen;
}

bool dneasy_parse_ip4(dneasy_ip *ip, const char *s) {
	uint32_t tn = 0;
	uint16_t port = 0;

	uint8_t parts[4];
	uint8_t parts_pos = 0;
	uint8_t st = 0;
	while (true) {
		if (st == 0) {
			// begin parsing part (number)
			if (*s >= '0' && *s <= '9') {
				tn = *s - '0';
				st = 1;
			} else {
				return false;
			}
		} else if (st == 1) {
			// at least one digit of number parsed
			if (*s >= '0' && *s <= '9') {
				if (tn == 0) {
					// leading zero on number, as in 01.2.3.4
					return false;
				} else {
					tn = tn * 10 + (*s - '0');
					if (tn > 0xff) {
						return false;
					}
				}
			} else if (*s == '.' || *s == ':' || *s == '\0') {
				parts[parts_pos++] = tn;
				if (*s == '.') {
					if (parts_pos == 4) {
						// to many parts
						return false;
					}
					st = 0;
				} else if (*s == ':') {
					st = 2;
				} else {
					// got 4 parts and finished.
					break;
				}
			} else {
				return false;
			}
		} else if (st == 2) {
			// begin parsing port
			if (*s >= '1' && *s <= '9') {
				tn = *s - '0';
				st = 3;
			} else {
				return false;
			}
		} else {
			// at least one digit of port parsed
			if (*s >= '0' && *s <= '9') {
				tn = (tn * 10) + (*s - '0');
				if (tn > 0xffff) {
					return false;
				}
			} else if (*s == '\0') {
				port = tn;
				break;
			} else {
				return false;
			}
		}
		s++;
	}
	if (parts_pos == 4) {
		ip->type = DNEASY_IP4;
		memcpy(ip->addr, parts, 4);
		memset(ip->addr + 4, 0, sizeof(ip->addr) - 4);
		ip->port = port;
		return true;
	}
	return false;
}

bool dneasy_parse_ip6(dneasy_ip *ip, const char *s) {
	// TODO: implement
	return false;
}

bool dneasy_parse_ip(dneasy_ip *ip, const char *s) {
	if (dneasy_parse_ip4(ip, s)) {
		return true;
//	} else if (dneasy_parse_ip6(ip, s)) {
//		return true;
	} else {
		return false;
	}
}

#define RESOLVE_BUF_SIZE 120

bool dneasy_resolve(dneasy_ip *ip, uint32_t *ttl, const char *host, const dneasy_ip *dns, dneasy_trx_t trx) {
	uint8_t buf[RESOLVE_BUF_SIZE];

	dneasy_ip dns2;
	memcpy(&dns2, dns, sizeof(dneasy_ip));
	if (dns2.port == 0) {
		dns2.port = 53;  // default dns port
	}
	ssize_t got = build_req(buf, RESOLVE_BUF_SIZE, host);
	got = trx(buf, got, RESOLVE_BUF_SIZE, &dns2);
	if (got < 12) {
		// communication fail (<0) or response too short for dns
		return false;
	}

	// end points to first mem address that is _not_ part of the response
	// if parsing reaches this, we need to stop!
	uint8_t *end = buf + got;
	// number of queries
	uint16_t qdcnt = ParseUInt16BigEndian(buf + 4);
	// number of answers
	uint16_t ancnt = ParseUInt16BigEndian(buf + 6);
	if (ancnt < 1) {
		// no answer in dns message
		return false;
	}

	// skip header (12 bytes)
	const uint8_t *p = buf + 12;
	// skip question part (one at a time, we have no absolute length)
	for (int i = 0; i < qdcnt; i++) {
		// name in question has dynamic length
		p = skip_name(p, end);
		if (p == NULL) {
			return false;
		}
		p += 4;
		if (p >= end) {
			return false;
		}
	}

	// p now points to beginning of first answer:
	for (int i = 0; i < ancnt; i++) {
		// we do not care for the name, we only questioned a single name
		p = skip_name(p, end);
		if (p == NULL) {
			return false;
		}
		dns_answer a;
		ssize_t read = parse_answer(&a, p, end);
		if (read < 1) {
			return false;
		}
		p += read;
		if (a.rdata + a.rdlen > end) {
			return false;
		}
		if (a.type == 0x0001 && a.class == 0x0001 && a.rdlen == 4) {
			// IPv4
			ip->type = DNEASY_IP4;
			ip->port = 0;
			memcpy(ip->addr, a.rdata, 4);
			if (ttl != NULL) {
				*ttl = a.ttl;
			}
			return true;
		} else if (a.type == 28 && a.rdlen == 16) {
			// IPv6
			ip->type = DNEASY_IP6;
			ip->port = 0;
			memcpy(ip->addr, a.rdata, 16);
			if (ttl != NULL) {
				*ttl = a.ttl;
			}
			return true;
		} else {
			Log("NO\n");
			return false;
		}
	}
	return false;
}

bool dneasy_resolve_list(dneasy_ip *ip, uint32_t *ttl, const char *host, const dneasy_ip *dns_list, size_t list_size,
						 dneasy_trx_t trx) {
	const dneasy_ip *dns = dns_list;
	for (int i = 0; i < list_size; i++) {
		if (dneasy_resolve(ip, ttl, host, &(dns[i]), trx)) {
			return true;
		}
	}
	return false;
}

const char *dneasy_ip_to_string(dneasy_ip *ip) {
	static char buf[20];
	if (ip->type == DNEASY_IP4) {
		if (ip->port) {
			snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
					 ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3], ip->port);
		} else {
			snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
					 ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
		}
		return buf;
	} else if (ip->type == DNEASY_IP6) {
		// TODO: ipv6
		return NULL;
	} else {
		return NULL;
	}
}

#ifdef _GNU_SOURCE
#define my_strchrnul(a,b) strchrnul(a,b)
#else
static char *my_strchrnul(const char *s, int c) {
	char *r = strchr(s, c);
	if (r == NULL) {
		r = strchr(s, '\0');
	}
	return r;
}
#endif

ssize_t dneasy_parse_server_list(dneasy_ip *ips, size_t size, const char *list) {
	char ip[45];
	const char *p, *last;

	// count number of entries in list (number of commas +1):
	size_t addrCnt = 1;
	for (p = list; *p; p++) {
		if (*p == ',') {
			addrCnt++;
		}
	}

	if (addrCnt > size) {
		return -1;
	}

	p = list;
	ssize_t n = 0;
	while (*p) {
		if (n >= size) {
			// this will never happen
			return -5;
		}
		last = p;
		p = my_strchrnul(p, ',');
		size_t l = p - last;
		if (l < 3) {
			// ip too short
			return -2;
		}
		if (l > sizeof(ip)) {
			// ip too long
			return -3;
		}
		// copy ip to local buffer (need 0-termination)
		memset(ip, 0, sizeof(ip));
		memcpy(ip, last, l);
//		Log("ip: '%s'\n", ip);
		dneasy_ip *addr = &(ips[n++]);
		if (!dneasy_parse_ip(addr, ip)) {
//			Log("invalid ip address\n");
			return -4;
		}
		if (addr->port == 0) {
			addr->port = 53;
		}
		// skip ','
		if (*p) {
			p++;
		}
	}
	return n;
}

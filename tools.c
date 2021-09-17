#include "tools.h"

uint32_t ParseUInt32BigEndian(const uint8_t* b) {
	return ((uint32_t)(b[0]) << 24u) | ((uint32_t)(b[1]) << 16u) | ((uint32_t)(b[2]) << 8u) | ((uint32_t)(b[3]) << 0u);
}

uint16_t ParseUInt16BigEndian(const uint8_t* b) {
	uint16_t v = ((uint16_t)b[0]) << 8u;
	return v | ((uint16_t)b[1]);
}

uint8_t MarshalUInt16BigEndian(uint8_t *to, uint16_t value) {
	to[0] = (uint8_t) (value >> 8u);
	to[1] = (uint8_t) (value >> 0u);
	return 2;
}


void LogBytes(const uint8_t* buf, size_t len) {
	for (size_t i = 0; i < len; i++) {
		Log("%02X ", buf[i]);
	}
}

void LogBytesLine(const char *pre, const uint8_t* buf, size_t len) {
	Log("%s", pre);
	LogBytes(buf, len);
	Log("\n");
}

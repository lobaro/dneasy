#pragma once

#include <stdio.h>
#include <stdint-gcc.h>
#include <stddef.h>

#define Log printf

#ifndef TRACE
#define TRACE() Log("TRACE: %d:%s\n", __LINE__, __FILE__)
#endif

uint32_t ParseUInt32BigEndian(const uint8_t* b);
uint16_t ParseUInt16BigEndian(const uint8_t* b);
uint8_t MarshalUInt16BigEndian(uint8_t *to, uint16_t value);
void LogBytes(const uint8_t* buf, size_t len);
void LogBytesLine(const char *pre, const uint8_t* buf, size_t len);


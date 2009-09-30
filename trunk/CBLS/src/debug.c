/*
 * bindump.c
 *
 *  Created on: Sep 28, 2009
 *      Author: Scott
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include "sys_deps.h"
#include "bnls.h"

extern void cbls_log (const char *fmt, ...);
#define MIN(x, y) ((x < y) ? (x) : (y))

void
bindump(char *data, int len) {
	int i, j, pos;
	char buf[67];
	for(i = 0; i < len; i += 16) {
		pos = 0;

		// First pass is hex
		for(j = i; j < MIN(len, i+16); j++) {
			int c = data[j];
			c &= 0xFF;
			pos += sprintf(buf+pos, "%02X ", c);
		}
		for(; j < i+16; j++)
			pos += sprintf(buf+pos, "   ");

		// Second pass is chars; display dots for non-ASCII
		for(j = i; j < MIN(len, i+16); j++) {
			int c = data[j];
			c &= 0xFF;
			if((c < 0x20) || (c > 0x7F))
				c = '.';
			pos += sprintf(buf+pos, "%c", c);
		}
		// No need to pad spaces; it's the end of the line
		cbls_log("%04X %s", i, buf);
	}
}

void
packet_log(char *comment, struct bnls_hdr *packet) {
	cbls_log("%s 0x%02X[%d]", comment, packet->id, packet->len);
	bindump((void*)packet, packet->len);
}

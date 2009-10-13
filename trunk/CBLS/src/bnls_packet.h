/*
 * bnls_packet.h
 *
 *  Created on: Sep 30, 2009
 *      Author: Scott
 */

#ifndef BNLS_PACKET_H_
#define BNLS_PACKET_H_

#include "cbls.h"

struct packet_reader {
	struct cbls_conn *cbls;
	struct bnls_hdr *ih;
	int pos;
};

void read_init(struct packet_reader *pr, struct cbls_conn *cbls);
int read_valid(struct packet_reader *pr);
int read_ready(struct packet_reader *pr);
int read_raw(struct packet_reader *pr, void *dest, int len);
int read_byte(struct packet_reader *pr, uint8_t *dest);
int read_word(struct packet_reader *pr, uint16_t *dest);
int read_dword(struct packet_reader *pr, uint32_t *dest);
int read_qword(struct packet_reader *pr, uint64_t *dest);
void* read_void(struct packet_reader *pr, int len);
char* read_string(struct packet_reader *pr);
void read_end(struct packet_reader *pr);

struct packet_writer {
	struct cbls_conn *cbls;
	struct bnls_hdr *oh;
	int qbuf_offset;
};

void write_init(struct packet_writer *pw, struct cbls_conn *cbls, int packetid, int min_length);
void write_raw(struct packet_writer *pw, void *data, int len);
void write_byte(struct packet_writer *pw, uint8_t value);
void write_word(struct packet_writer *pw, uint16_t value);
void write_dword(struct packet_writer *pw, uint32_t value);
void write_qword(struct packet_writer *pw, uint64_t value);
void write_string(struct packet_writer *pw, char *value);
void write_end(struct packet_writer *pw);

#endif /* CBLS_PACKET_H_ */

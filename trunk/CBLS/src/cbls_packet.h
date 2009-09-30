/*
 * cbls_packet.h
 *
 *  Created on: Sep 30, 2009
 *      Author: sanderson
 */

#ifndef CBLS_PACKET_H_
#define CBLS_PACKET_H_

struct packet_writer {
	struct cbls_conn *cbls;
	struct bnls_hdr *oh;
	int qbuf_offset;
};

void write_init(struct packet_writer *pw, struct cbls_conn *cbls, int packetid, int min_length);
void write_raw(struct packet_writer *pw, void *data, int len);
void write_dword(struct packet_writer *pw, u_int32_t value);
void write_end(struct packet_writer *pw);

#endif /* CBLS_PACKET_H_ */

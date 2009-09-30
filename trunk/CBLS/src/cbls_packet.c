/*
 * cbls_packet.c
 *
 *  Created on: Sep 30, 2009
 *      Author: sanderson
 */

#include <string.h>
#include "sys_types.h"
#include "sys_net.h"
#include "cbls.h"
#include "cbls_packet.h"
#include "bnls.h"
#include "cbls_fd.h"
//#include "debug.h" /* for packet_log() */

/**
 * Initialize a packet writer. The length is just a hint; you may go over.
 */
void
write_init(struct packet_writer *pw, struct cbls_conn *cbls, int packetid, int min_length) {
	struct bnls_hdr *oh;
	struct qbuf *out;

	out = &cbls->out;

	pw->qbuf_offset = out->len;
	qbuf_set(out, out->pos, pw->qbuf_offset + SIZEOF_BNLS_HDR + min_length);
	oh = (struct bnls_hdr *)&out->buf[out->pos + pw->qbuf_offset];
	oh->id = packetid;
	oh->len = SIZEOF_BNLS_HDR;

	pw->cbls = cbls;
	pw->oh = oh;
}

void
write_raw(struct packet_writer *pw, void *data, int len) {
	struct qbuf *out = &pw->cbls->out;
    struct bnls_hdr *oh = pw->oh;

    int write_pos = oh->len - SIZEOF_BNLS_HDR;
    oh->len += len;
    if(out->len < pw->qbuf_offset + oh->len)
        qbuf_set(out, out->pos, pw->qbuf_offset + oh->len);
    memcpy(&oh->data[write_pos], data, len);
}

void
write_dword(struct packet_writer *pw, u_int32_t value) {
	write_raw(pw, &value, 4);
}

void
write_end(struct packet_writer *pw) {
	cbls_fd_set(pw->cbls->fd, FDW);

	/*packet_log("SEND", pw->oh);*/
}

/*
 * cbls_protocol.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include "sys_types.h"
#include "sys_net.h"
#include "cbls.h"
#include "bnls.h"
#include "cbls_fd.h"
#include "debug.h"

extern void cbls_log (const char *fmt, ...);

// cbls->read_in has new data off the wire; copy data to cbls->in
u_int32_t
decode (struct qbuf *qdst, struct qbuf *qsrc)
{
	u_int32_t len, max, inused, inlen;

	inlen = qsrc->len;
	if (!inlen)
		return 0;
	inused = 0;
	len = inlen;
	qsrc->pos = 0;

	max = qdst->len;
	if (max && inlen > max) {
		inused = max;
		len = max;
	} else {
		inused = inlen;
		len = inlen;
	}

	if (qdst->len < len)
		qbuf_set(qdst, qdst->pos, len);
	memcpy(&qdst->buf[qdst->pos], &qsrc->buf[qsrc->pos], len);
	if (inlen != inused) {
		/* Move unread source data to the front */
		memmove(&qsrc->buf[0], &qsrc->buf[inused], inlen - inused);
	}
	qsrc->pos = inlen - inused;
	qsrc->len -= inused;
	qdst->pos += len;
	if (len > qdst->len) {
		/* More data than expected */
		qdst->len = 0;
	} else
		qdst->len -= len;

	return (qdst->len == 0) ? 1 : 0;
}

struct packet_writer {
	struct cbls_conn *cbls;
	struct bnls_hdr *oh;
	int qbuf_offset;
};

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

void
cbls_protocol_rcv(struct cbls_conn *cbls)
{
	struct qbuf *in;
	struct bnls_hdr *hdr;
	struct packet_writer pw;

	in = &cbls->in;

	/*cbls_log("cbls_protocol_recv[%d] qbuf size is %d", cbls->fd, in->pos);*/

	while(in->pos >= SIZEOF_BNLS_HDR) {
		hdr = (struct bnls_hdr *)&in->buf[0];

		if(in->pos < hdr->len) {
			/*cbls_log("Packet incomplete [%d/%d]", in->pos, hdr->len);*/
			break;
		}

		switch(hdr->id) {
		case BNLS_NULL:
			break;
			
		case BNLS_AUTHORIZE:
			/* (STRING) Bot ID
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZE, 4);
			write_dword(&pw, 0); // (DWORD) Server code
			write_end(&pw);
			break;

		case BNLS_AUTHORIZEPROOF:
			/* (DWORD) Checksum
			 */
			write_init(&pw, cbls, BNLS_AUTHORIZEPROOF, 4);
			write_dword(&pw, 0); // (DWORD) 0=Authorized, 1=Unauthorized
			write_end(&pw);
			break;

		case BNLS_REQUESTVERSIONBYTE: {
			/* (DWORD) Product ID
			 */
			u_int32_t prod = *(u_int32_t*)&hdr->data[0];
			u_int32_t verb;
			if(hdr->len < 4)
				prod = 0;
			switch(prod) {
			case 1: case 2:  verb = 0xd3; break;
			case 3:          verb = 0x4f; break;
			case 4: case 5:  verb = 0x0c; break;
			case 6:          verb = 0xa9; break;
			case 7: case 8:  verb = 0x17; break;
			case 9: case 10: verb = 0x2a; break;
			case 11:         verb = 0x1a; break;
			default:
				prod = 0;
				verb = 0;
			}

			write_init(&pw, cbls, BNLS_REQUESTVERSIONBYTE, 8);
			write_dword(&pw, prod); // (DWORD) Product ID (0 for error)
			write_dword(&pw, verb); // (DWORD) Version byte
			write_end(&pw);
			break; }

		default:
			cbls_log("Received unknown packet %d[%d]", hdr->id, hdr->len);
			packet_log("RECV", hdr);
		}

		// Remove the packet from the buffer
		if(in->pos != hdr->len)
			memmove(&in->buf[0], &in->buf[hdr->len], in->pos - hdr->len);
		in->pos -= hdr->len;
	}
}

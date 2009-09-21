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

void
cbls_protocol_rcv(struct cbls_conn *cbls)
{
	struct qbuf *in, *out;
	struct bnls_hdr *hdr, *oh;

	in = &cbls->in;
	out = &cbls->out;

	cbls_log("cbls_protocol_recv[%d] qbuf size is %d", cbls->fd, in->pos);

	while(in->pos >= SIZEOF_BNLS_HDR) {
		hdr = (struct bnls_hdr *)&in->buf[0];

		if(in->pos < hdr->len) {
			cbls_log("Packet incomplete [%d/%d]", in->pos, hdr->len);
			break;
		}

		switch(hdr->id) {
		case BNLS_AUTHORIZE:
			cbls_log("[%d] BNLS_AUTHORIZE", cbls->fd);
			/* (STRING) Bot ID
			 */
			if(out->len < SIZEOF_BNLS_HDR + 4)
				qbuf_set(out, out->pos, SIZEOF_BNLS_HDR + 4);
			oh = (struct bnls_hdr *)&out->buf[out->pos + out->len];
			oh->id = BNLS_AUTHORIZE;
			oh->len += SIZEOF_BNLS_HDR + 4;
			*(u_int32_t*)&oh->data[0] = 0; // (DWORD) Server code
			cbls_fd_set(cbls->fd, FDW);
			break;

		case BNLS_AUTHORIZEPROOF:
			cbls_log("[%d] BNLS_AUTHORIZEPROOF", cbls->fd);
			/* (DWORD) Checksum
			 */
			if(out->len < SIZEOF_BNLS_HDR + 4)
				qbuf_set(out, out->pos, SIZEOF_BNLS_HDR + 4);
			oh = (struct bnls_hdr *)&out->buf[out->pos + out->len];
			oh->id = BNLS_AUTHORIZEPROOF;
			oh->len += SIZEOF_BNLS_HDR + 4;
			*(u_int32_t*)&oh->data[0] = 0; // (DWORD) 0=Authorized, 1=Unauthorized
			cbls_fd_set(cbls->fd, FDW);
			break;

		case BNLS_REQUESTVERSIONBYTE:
			cbls_log("[%d] BNLS_REQUESTVERSIONBYTE", cbls->fd);
			/* (DWORD) Product ID
			 */
			if(out->len < SIZEOF_BNLS_HDR + 8)
				qbuf_set(out, out->pos, SIZEOF_BNLS_HDR + 8);
			oh = (struct bnls_hdr *)&out->buf[out->pos + out->len];
			oh->id = BNLS_REQUESTVERSIONBYTE;
			oh->len += SIZEOF_BNLS_HDR + 8;
			*(u_int32_t*)&oh->data[0] = 0; // (DWORD) Product ID (0 for error)
			*(u_int32_t*)&oh->data[4] = 0; // (DWORD) Version byte
			cbls_fd_set(cbls->fd, FDW);
			break;

		default:
			cbls_log("Recieved unknown packet %d[%d]", hdr->id, hdr->len);
		}

		// Remove the packet from the buffer
		if(in->pos != hdr->len)
			memmove(&in->buf[0], &in->buf[hdr->len], in->pos - hdr->len);
		in->pos -= hdr->len;
	}
}

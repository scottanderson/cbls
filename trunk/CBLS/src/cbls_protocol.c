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
	struct qbuf *in = &cbls->in;

	cbls_log("cbls_protocol_recv[%d] qbuf size is %d", cbls->fd, in->pos);

	if(in->pos < SIZEOF_BNLS_HDR) {
		/* Not enough data to form a header */
		cbls_log("Not enough data to form a header yet...");
		return;
	}

	struct bnls_hdr *header = (struct bnls_hdr *)in->buf;

	if(in->pos < header->len) {
		cbls_log("Packet incomplete [%d/%d]", in->pos, header->len);
		return;
	}

	switch(header->id) {
	case BNLS_AUTHORIZE:
		/* (STRING) Bot ID
		 */
		break;
	default:
		cbls_log("Recieved unknown packet %d[%d]", header->id, header->len);
	}

	// Mark the packet read
	in->pos += header->len;
	in->len -= header->len;
}

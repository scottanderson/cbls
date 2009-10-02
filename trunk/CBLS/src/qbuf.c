/*
 * qbuf.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include "xmalloc.h"
#include "qbuf.h"

#define QBUF_SIZE_LIMIT	0x1000

void
qbuf_set (struct qbuf *q, u_int32_t pos, u_int32_t len)
{
	u_int32_t size = q->pos + q->len;
	/* if the size was very large, reallocate */
	int need_realloc = (size < pos + len) || (size > QBUF_SIZE_LIMIT);

	q->pos = pos;
	q->len = len;
	if (need_realloc)
		q->buf = xrealloc(q->buf, q->pos + q->len + 1); /* +1 for null */
}

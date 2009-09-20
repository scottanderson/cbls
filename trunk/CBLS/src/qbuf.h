/*
 * qbuf.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef QBUF_H_
#define QBUF_H_

struct qbuf {
	u_int32_t pos, len;
	u_int8_t *buf;
};

void qbuf_set (struct qbuf *q, u_int32_t pos, u_int32_t len);

#endif /* QBUF_H_ */

/*
 * qbuf.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef QBUF_H_
#define QBUF_H_

#include <stdint.h>

struct qbuf {
    uint32_t pos, len;
    uint8_t *buf;
};

void qbuf_set (struct qbuf *q, uint32_t pos, uint32_t len);

#endif /* QBUF_H_ */

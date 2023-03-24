/*
 * protocol.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include "cbls.h"

uint32_t decode (struct qbuf *qdst, struct qbuf *qsrc);
void cbls_protocol_decide(struct cbls_conn *cbls);
void bnls_protocol_rcv(struct cbls_conn *cbls);
void http_protocol_rcv(struct cbls_conn *cbls);

#endif /* PROTOCOL_H_ */

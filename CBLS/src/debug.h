/*
 * debug.h
 *
 *  Created on: Sep 28, 2009
 *      Author: sanderson
 */

#ifndef DEBUG_H_
#define DEBUG_H_

void bindump(char *data, int len);
void packet_log(char *comment, struct bnls_hdr *packet);

#endif /* DEBUG_H_ */

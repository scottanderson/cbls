/*
 * inetlib.h
 *
 *  Created on: Sep 18, 2009
 *      Author: Scott
 */

#ifndef INETLIB_H_
#define INETLIB_H_

void inaddr2str (char abuf[HOSTLEN+1], struct SOCKADDR_IN *sa);
int inet_ntoa_r (struct in_addr in, char *buf, size_t buflen);

#endif /* INETLIB_H_ */

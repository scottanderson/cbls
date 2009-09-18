/*
 * inetlib.h
 *
 *  Created on: Sep 18, 2009
 *      Author: Scott
 */

#ifndef INETLIB_H_
#define INETLIB_H_

#if defined(__WIN32__)
//FIXME: this should go somewhere else
typedef unsigned __int8 u_int8_t;
typedef unsigned __int16 u_int16_t;
typedef unsigned __int32 u_int32_t;
#endif

/* IPv6 */
#ifdef CONFIG_IPV6
#define HOSTLEN 63
#define SOCKADDR_IN sockaddr_in6
#define SIN_PORT sin6_port
#define SIN_FAMILY sin6_family
#define SIN_ADDR sin6_addr
#define S_ADDR s6_addr
#define AFINET AF_INET6
#define IN_ADDR in6_addr
#else
/* IPv4 */
#define HOSTLEN 15
#define SOCKADDR_IN sockaddr_in
#define SIN_PORT sin_port
#define SIN_FAMILY sin_family
#define SIN_ADDR sin_addr
#define S_ADDR s_addr
#define AFINET AF_INET
#define IN_ADDR in_addr
#endif

void inaddr2str (char abuf[HOSTLEN+1], struct SOCKADDR_IN *sa);
int inet_ntoa_r (struct in_addr in, char *buf, size_t buflen);

#endif /* INETLIB_H_ */

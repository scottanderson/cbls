#ifndef __CBLS_SYS_NET_H
#define __CBLS_SYS_NET_H

#if defined(__WIN32__)
#define __USE_W32_SOCKETS
#include <windows.h>
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

/* IPv6 */
#ifdef CONFIG_IPV6
#define HOSTLEN 63
#define SOCKADDR_IN sockaddr_in6
#define SOCKADDR sockaddr6
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
#define SOCKADDR sockaddr
#define SIN_PORT sin_port
#define SIN_FAMILY sin_family
#define SIN_ADDR sin_addr
#define S_ADDR s_addr
#define AFINET AF_INET
#define IN_ADDR in_addr
#endif

#endif

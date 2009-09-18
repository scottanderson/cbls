
#ifndef CBLS_H_INCLUDED
#define CBLS_H_INCLUDED

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

struct qbuf {
	u_int32_t pos, len;
	u_int8_t *buf;
};

struct cbls_conn {
	struct cbls_conn *next, *prev;
	int fd;
	void (*rcv)(struct cbls_conn *);
	struct qbuf in, out;
	struct SOCKADDR_IN *sockaddr;

	u_int16_t uid;

	struct timeval login_tv;
	struct timeval idle_tv;
};

struct cbls_file {
	union {
		void *ptr;
		struct cbls_conn *cbls;
	} conn;
	void (*ready_read)(int fd);
	void (*ready_write)(int fd);
};

extern struct cbls_file *cbls_files;

extern int cbls_open_max;
extern int nr_open_files;

extern int high_fd;

extern fd_set cbls_rfds, cbls_wfds;

extern void cbls_fd_add (int fd);
extern void cbls_fd_del (int fd);
extern void cbls_fd_set (int fd, int rw);
extern void cbls_fd_clr (int fd, int rw);
#define FDR	1
#define FDW	2

#endif

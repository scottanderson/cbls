
#ifndef CBLS_H_INCLUDED
#define CBLS_H_INCLUDED

#if defined(__WIN32__)
//FIXME: this should go somewhere else
typedef unsigned __int8 u_int8_t;
typedef unsigned __int16 u_int16_t;
typedef unsigned __int32 u_int32_t;
#endif

struct qbuf {
	u_int32_t pos, len;
	u_int8_t *buf;
};

struct cbls_conn {
	struct cbls_conn *next, *prev;
	int fd;
	int wfd;
	int identfd;
	void (*rcv)(struct cbls_conn *);
	void (*real_rcv)(struct cbls_conn *);
	struct qbuf in, out;
	struct qbuf read_in;
	struct SOCKADDR_IN *sockaddr;

	u_int16_t uid;

	struct timeval login_tv;
	struct timeval idle_tv;
};

#endif

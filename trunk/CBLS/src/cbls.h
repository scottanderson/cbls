
#ifndef CBLS_H_INCLUDED
#define CBLS_H_INCLUDED

#if !defined(u_int32_t)
//FIXME: this should go somewhere else
#define u_int8_t unsigned __int8
#define u_int16_t unsigned __int16
#define u_int32_t unsigned __int32
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

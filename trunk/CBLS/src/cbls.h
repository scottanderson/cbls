/*
 * cbls.h
 *
 *  Created on: Sep 15, 2009
 *      Author: Scott
 */

#ifndef CBLS_H_INCLUDED
#define CBLS_H_INCLUDED

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

#endif

/*
 * cbls.h
 *
 *  Created on: Sep 15, 2009
 *      Author: Scott
 */

#ifndef CBLS_H_INCLUDED
#define CBLS_H_INCLUDED

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

/*
 * cbls_fd.h
 *
 *  Created on: Sep 18, 2009
 *      Author: Scott
 */

#ifndef CBLS_FD_H_
#define CBLS_FD_H_

extern int high_fd;

extern fd_set cbls_rfds, cbls_wfds;

extern void cbls_fd_add (int fd);
extern void cbls_fd_del (int fd);
extern void cbls_fd_set (int fd, int rw);
extern void cbls_fd_clr (int fd, int rw);
#define FDR	1
#define FDW	2

#endif /* CBLS_FD_H_ */

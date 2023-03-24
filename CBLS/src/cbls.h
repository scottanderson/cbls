/*
 * cbls.h
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#ifndef CBLS_H_
#define CBLS_H_

#include <sys/time.h>
#include "sys_net.h"
#include "qbuf.h"
#include "bncsutil/nls.h"

struct cbls_conn {
    struct cbls_conn *next, *prev;
    int fd;
    void (*rcv)(struct cbls_conn *);
    struct qbuf in, out;
    struct qbuf read_in;
    struct SOCKADDR_IN sockaddr;

    uint16_t uid;

    struct timeval login_tv;
    struct timeval idle_tv;

    uint32_t nls_rev;
    nls_t *nls;
    char *new_password;
};

struct cbls_conn *cbls_new (void);
void cbls_accepted (struct cbls_conn *cbls);
void cbls_close (struct cbls_conn *cbls);

#endif /* CBLS_H_ */

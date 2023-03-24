/*
 * cbls_fd.c
 *
 *  Created on: Sep 18, 2009
 *      Author: Scott
 */

#include "cbls_fd.h"

int high_fd = 0;
fd_set cbls_rfds, cbls_wfds;

void cbls_fd_add (int fd)
{
    if (high_fd < fd)
        high_fd = fd;
}

void cbls_fd_del (int fd)
{
    if (high_fd == fd) {
        for (fd--; fd && !FD_ISSET(fd, &cbls_rfds); fd--)
            ;
        high_fd = fd;
    }
}

void cbls_fd_set (int fd, int rw)
{
    if (rw & FDR)
        FD_SET(fd, &cbls_rfds);
    if (rw & FDW)
        FD_SET(fd, &cbls_wfds);
}

void cbls_fd_clr (int fd, int rw)
{
    if (rw & FDR)
        FD_CLR(fd, &cbls_rfds);
    if (rw & FDW)
        FD_CLR(fd, &cbls_wfds);
}

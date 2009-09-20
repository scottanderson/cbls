/*
 * cbls.c
 *
 *  Created on: Sep 20, 2009
 *      Author: Scott
 */

#include <sys/time.h>
#include <string.h>
#include "sys_types.h"
#include "sys_deps.h"
#include "sys_net.h"
#include "xmalloc.h"
#include "cbls_fd.h"
#include "cbls_server.h"
#include "cbls.h"
#include "cbls_protocol.h"

u_int16_t ncbls_conns = 0;

struct cbls_conn __cbls_list, *cbls_list = &__cbls_list, *cbls_tail = &__cbls_list;

/*
 * Allocate a new cbls connection and initialize it
 * Suitable to call before checking the banlist
 * Must set cbls->fd and cbls->sockaddr after calling
 */
struct cbls_conn *
cbls_new (void)
{
	struct cbls_conn *cbls;

	cbls = xmalloc(sizeof(struct cbls_conn));
	memset(cbls, 0, sizeof(struct cbls_conn));
	/* cbls->next = 0; */
	cbls->prev = cbls_tail;
	cbls_tail->next = cbls;
	cbls_tail = cbls;
	ncbls_conns++;
	//cbls->access_extra.can_login = 1;

	return cbls;
}

void
cbls_close (struct cbls_conn *cbls)
{
	int fd = cbls->fd;
	char abuf[HOSTLEN+1];
	int wr;
	u_int16_t i;

	socket_close(fd);
	nr_open_files--;
	cbls_fd_clr(fd, FDR|FDW);
	cbls_fd_del(fd);
	memset(&cbls_files[fd], 0, sizeof(struct cbls_file));
	inaddr2str(abuf, &cbls->sockaddr);
	cbls_log("%s:%u - %u - cbls connection closed",
		abuf, ntohs(cbls->sockaddr.SIN_PORT),
		cbls->uid);
	//timer_delete_ptr(cbls);
	if (cbls->next)
		cbls->next->prev = cbls->prev;
	if (cbls->prev)
		cbls->prev->next = cbls->next;
	if (cbls_tail == cbls)
		cbls_tail = cbls->prev;
	if (cbls->read_in.buf)
		xfree(cbls->read_in.buf);
	if (cbls->in.buf)
		xfree(cbls->in.buf);
	if (cbls->out.buf)
		xfree(cbls->out.buf);
	xfree(cbls);
	ncbls_conns--;
}

#define READ_BUFSIZE	1024
extern unsigned int decode (struct cbls_conn *cbls);

static void
cbls_read (int fd)
{
	ssize_t r;
	struct cbls_conn *cbls = cbls_files[fd].conn.cbls;
	struct qbuf *in = &cbls->read_in;
	int do_reset;
	int err;

	if (in->len == 0) {
		qbuf_set(in, in->pos, READ_BUFSIZE);
		in->len = 0;
	}
	r = socket_read(fd, &in->buf[in->pos], READ_BUFSIZE-in->len);
	if (r <= 0) {
		err = socket_errno();
#if defined(__WIN32__)
		if (r == 0 || (r < 0 && err != WSAEWOULDBLOCK && err != WSAEINTR)) {
#else
		if (r == 0 || (r < 0 && err != EWOULDBLOCK && err != EINTR)) {
#endif
			/*cbls_log("cbls_read; %d %s", r, strerror(errno));*/
			cbls_close(cbls);
		}
	} else {
		in->len += r;
		for (;;) {
			r = decode(cbls);
			if (!r)
				break;
			if (cbls->rcv) {
				do_reset = proto_should_reset(cbls);
				cbls->rcv(cbls);
				/* cbls->rcv could have called cbls_close */
				if (!cbls_files[fd].conn.cbls)
					return;
				if (do_reset)
					goto reset;
			} else {
reset:
				/* Check idle status after a transaction is completed */
//				if (!cbls->access_extra.can_login) {
//					test_away(cbls);
//				}
				proto_reset(cbls);
			}
		}
	}
}

static void
cbls_write (int fd)
{
	ssize_t r;
	struct cbls_conn *cbls = cbls_files[fd].conn.cbls;
	int err;

	if (cbls->out.len == 0) {
		/*cbls_log("cbls->out.len == 0 but cbls_write was called...");*/
		cbls_fd_clr(fd, FDW);
		return;
	}
	r = socket_write(fd, &cbls->out.buf[cbls->out.pos], cbls->out.len);
	if (r <= 0) {
		err = socket_errno();
#if defined(__WIN32__)
		if (r == 0 || (r < 0 && err != WSAEWOULDBLOCK && err != WSAEINTR)) {
#else
		if (r == 0 || (r < 0 && err != EWOULDBLOCK && err != EINTR)) {
#endif
			/*cbls_log("cbls_write(%u); %d %s", cbls->out.len, r, strerror(errno));*/
			cbls_close(cbls);
		}
	} else {
		cbls->out.pos += r;
		cbls->out.len -= r;
		if (!cbls->out.len) {
			cbls->out.pos = 0;
			cbls->out.len = 0;
			cbls_fd_clr(fd, FDW);
		}
	}
}

/*
 * Call after checking the banlist
 */
void
cbls_accepted (struct cbls_conn *cbls)
{
	int s = cbls->fd;

	cbls_files[s].ready_read = cbls_read;
	cbls_files[s].ready_write = cbls_write;
	cbls_files[s].conn.cbls = cbls;

	cbls->rcv = cbls_protocol_rcv;

	//timer_add_secs(10, login_timeout, cbls);

	/* qbuf_set(&cbls->in, 0, cbls_MAGIC_LEN); */
	qbuf_set(&cbls->in, 0, 0);
	cbls_fd_set(s, FDR);
}

/*
 * cbls.c
 *
 *  Created on: Sep 15, 2009
 *      Author: Scott
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <errno.h>
#include "sys_net.h"
#include "sys_types.h"
#include "sys_deps.h"
#include "inetlib.h"
#include "xmalloc.h"
#include "cbls.h"
#include "cbls_server.h"
#include "cbls_fd.h"

#if defined(__APPLE__)
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif

int cbls_open_max = 0;
struct cbls_file *cbls_files = 0;

int nr_open_files = 3;

struct timeval server_start_time;

static void loopZ (void) __attribute__((__noreturn__));

//struct timeval loopZ_timeval;

char *cbls_version = "0.1";


void
cbls_log (const char *fmt, ...)
{
	va_list ap;
	char buf[2048];
	int len;
	time_t t;
	struct tm *tm;

	time(&t);
	tm = localtime(&t);
	strftime(buf, 21, "%H:%M:%S %m/%d/%Y\t", tm);
	va_start(ap, fmt);
	len = vsnprintf(&buf[20], sizeof(buf) - 24, fmt, ap);
	va_end(ap);
	if (len == -1)
		len = sizeof(buf) - 24;
	len += 20;
	buf[len++] = '\n';
	write(/*log_fd*/1, buf, len);
	SYS_fsync(/*log_fd*/1);
}

int
get_open_max(void)
{
	int om;

#if defined(_SC_OPEN_MAX)
	om = sysconf(_SC_OPEN_MAX);
#elif defined(RLIMIT_NOFILE)
	{
		struct rlimit rlimit;

		if (getrlimit(RLIMIT_NOFILE, &rlimit)) {
			cbls_log("main: getrlimit: %s", strerror(errno));
			exit(1);
		}
		om = rlimit.rlim_max;
	}
#elif defined(HAVE_GETDTABLESIZE)
	om = getdtablesize();
#elif defined(OPEN_MAX)
	om = OPEN_MAX;
#else
	om = sizeof(fd_set)*8;
#endif

	if (om > (int)(FD_SETSIZE*sizeof(int)*8))
		om = (int)(FD_SETSIZE*sizeof(int)*8);

#if defined(__WIN32__)
	om = 4096;
#endif

	return om;
}

static void
loopZ (void)
{
	fd_set rfds, wfds;
	//struct timeval before, tv;

	//gettimeofday(&tv, 0);
	for (;;) {
		register int n, i;

		/*if (timer_list) {
			gettimeofday(&before, 0);
			timer_check(&tv, &before);
			if (timer_list)
				tv = timer_list->tv;
		}*/
		rfds = cbls_rfds;
		wfds = cbls_wfds;
		n = select(high_fd + 1, &rfds, &wfds, 0, /*timer_list ? &tv :*/ 0);
		if (n < 0) {
			if (errno != EINTR) {
				cbls_log("loopZ: select: %s", strerror(errno));
				exit(1);
			}
		}
		/*gettimeofday(&tv, 0);
		loopZ_timeval = tv;
		if (timer_list) {
			timer_check(&before, &tv);
		}*/
		if (n <= 0)
			continue;
		for (i = 0; i < high_fd + 1; i++) {
			if (FD_ISSET(i, &rfds) && FD_ISSET(i, &cbls_rfds)) {
				if (cbls_files[i].ready_read)
					cbls_files[i].ready_read(i);
				n--;
				if (!n)
					break;
			}
			if (FD_ISSET(i, &wfds) && FD_ISSET(i, &cbls_wfds)) {
				if (cbls_files[i].ready_write)
					cbls_files[i].ready_write(i);
				n--;
				if (!n)
					break;
			}
		}
	}
}

static void
listen_ready_read (int fd)
{
	int s;
	struct SOCKADDR_IN saddr;
	int siz = sizeof(saddr);
	char abuf[16];
	struct cbls_conn *cbls;

	s = accept(fd, (struct SOCKADDR *)&saddr, &siz);
	if (s < 0) {
		cbls_log("cbls: accept: %s", strerror(errno));
		return;
	}
	nr_open_files++;
	inaddr2str(abuf, &saddr);
	if (nr_open_files >= cbls_open_max) {
		cbls_log("%s:%u: %d >= cbls_open_max (%d)", abuf, ntohs(saddr.sin_port), s, cbls_open_max);
		socket_close(s);
		nr_open_files--;
		return;
	}

//	fd_closeonexec(s, 1);
//	socket_blocking(s, 0);
	if (high_fd < s)
		high_fd = s;

	cbls = cbls_new();
	cbls->fd = s;
	cbls->sockaddr = saddr;

	/*
	 * Make sure known bad addresses are banned before
	 * they can fill up the connection spam queue.
	 */
//	if (check_banlist(cbls))
//		return;
	cbls_log("%s:%u -- cbls connection accepted", abuf, ntohs(saddr.sin_port));

	cbls_accepted(cbls);
}

int
main(int argc __attribute__((__unused__)), char **argv __attribute__((__unused__)), char **envp)
{
#if defined(__WIN32__)
	/* init winsock */
	WSADATA wsadata;

	if(WSAStartup(1, &wsadata) != NO_ERROR) {
		cbls_log("WSAStartup() failed");
		exit(1);
	}
#endif

	cbls_open_max = get_open_max();
	cbls_files = xmalloc(cbls_open_max * sizeof(struct cbls_file));
	memset(cbls_files, 0, cbls_open_max * sizeof(struct cbls_file));
	FD_ZERO(&cbls_rfds);
	FD_ZERO(&cbls_wfds);

	int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_sock < 0) {
		cbls_log("socket() failed");
		exit(1);
	}

	int port = 9367;
#if defined(__WIN32__)
	struct hostent* thisHost = gethostbyname("");
	char *ip = inet_ntoa(*(struct in_addr *)*thisHost->h_addr_list);
	cbls_log("%s:%d", ip, port);
#endif

	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
#if defined(__WIN32__)
	saddr.sin_addr.s_addr = inet_addr(ip);
#endif

	if(bind(listen_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		cbls_log("bind() failed");
		exit(1);
	}

	if(listen(listen_sock, 5) < 0) {
		cbls_log("listen() failed");
		exit(1);
	}

	cbls_files[listen_sock].ready_read = listen_ready_read;
	cbls_fd_set(listen_sock, FDR);
	if (high_fd < listen_sock)
		high_fd = listen_sock;
//	fd_closeonexec(listen_sock, 1);
//	socket_blocking(listen_sock, 0);

	cbls_log("cbls version %s started", cbls_version);

	loopZ();

#if defined(__WIN32__)
	WSACleanup();
#endif
	return 0;
}

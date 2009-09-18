#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#if defined(__WIN32__)
#  include <winsock.h>
#else
#  include <netinet/in.h>
#endif
#include "cbls.h"


int cbls_open_max = 0;
struct cbls_file *cbls_files = 0;

int nr_open_files = 3;

int high_fd = 0;
fd_set cbls_rfds, cbls_wfds;
struct timeval server_start_time;

static void loopZ (void) __attribute__((__noreturn__));

struct timeval loopZ_timeval;

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
	//SYS_fsync(log_fd);
}

int get_open_max(void) {
	int om;

#if defined(_SC_OPEN_MAX)
	om = sysconf(_SC_OPEN_MAX);
#elif defined(RLIMIT_NOFILE)
	{
		struct rlimit rlimit;

		if (getrlimit(RLIMIT_NOFILE, &rlimit)) {
			hxd_log("main: getrlimit: %s", strerror(errno));
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

static void loopZ (void) {
	fd_set rfds, wfds;
	struct timeval before, tv;

	gettimeofday(&tv, 0);
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
		gettimeofday(&tv, 0);
		loopZ_timeval = tv;
		/*if (timer_list) {
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


int
inet_ntoa_r (struct in_addr in, char *buf, size_t buflen)
{
	u_int32_t addr = in.s_addr;
	register u_int8_t *addr_p = (u_int8_t *)&addr, *t;
	register unsigned int i, pos;
	u_int8_t tmp[4];

	for (i = 4, pos = 0; ; addr_p++) {
		i--;
		t = tmp;
		do {
			*t++ = "0123456789"[*addr_p % 10];
		} while (*addr_p /= 10);
		for (; t > tmp; pos++) {
			if (pos >= buflen)
				return -1;
			buf[pos] = *--t;
		}
		if (!i)
			break;
		if (pos >= buflen)
			return -1;
		buf[pos++] = '.';
	}

	if (pos >= buflen)
		return -1;
	buf[pos] = 0;

	return pos;
}

void
inaddr2str (char abuf[HOSTLEN+1], struct SOCKADDR_IN *sa)
{
#ifdef CONFIG_IPV6
	inet_ntop(AFINET, (char *)&sa->SIN_ADDR, abuf, HOSTLEN+1);
#else
	inet_ntoa_r(sa->SIN_ADDR, abuf, 16);
#endif
}

static void
listen_ready_read (int fd)
{
	int s;
	struct sockaddr_in saddr;
	int siz = sizeof(saddr);
	char abuf[16];
//	struct cbls_conn *cbls;

	s = accept(fd, (struct sockaddr *)&saddr, &siz);
	if (s < 0) {
		cbls_log("cbls: accept: %s", strerror(errno));
		return;
	}
	nr_open_files++;
	inaddr2str(abuf, &saddr);
	if (nr_open_files >= cbls_open_max) {
		cbls_log("%s:%u: %d >= cbls_open_max (%d)", abuf, ntohs(saddr.sin_port), s, cbls_open_max);
//		socket_close(s);
		nr_open_files--;
		return;
	}

//	fd_closeonexec(s, 1);
//	socket_blocking(s, 0);
	if (high_fd < s)
		high_fd = s;

//	cbls = cbls_new();
//	cbls->fd = s;
//	cbls->sockaddr = saddr;

	/*
	 * Make sure known bad addresses are banned before
	 * they can fill up the connection spam queue.
	 */
//	if (check_banlist(cbls))
//		return;
	cbls_log("%s:%u -- cbls connection accepted", abuf, ntohs(saddr.sin_port));

//	cbls_accepted(cbls);
}

int main(int argc __attribute__((__unused__)), char **argv __attribute__((__unused__)), char **envp)
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
	cbls_files = malloc(cbls_open_max * sizeof(struct cbls_file));
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

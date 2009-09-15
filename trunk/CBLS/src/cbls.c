#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
//#include "xmalloc.h"
#if defined(__WIN32__)
#  include <winsock2.h>
#else
#  include <linux/socket.h>
#  include <sys/select.h>
#endif
#include "cbls.h"


int high_fd = 0;
fd_set cbls_rfds, cbls_wfds;
struct timeval server_start_time;

char *cbls_version = "0.1";

int main(int argc __attribute__((__unused__)), char **argv __attribute__((__unused__)), char **envp)
{
#if defined(__WIN32__)
	/* init winsock */
	WSADATA wsadata;

	WSAStartup(1, &wsadata);
#endif

	FD_ZERO(&cbls_rfds);
	FD_ZERO(&cbls_wfds);

	printf("cbls version %s started", cbls_version);

#if defined(__WIN32__)
	WSACleanup();
#endif
	return 0;
}

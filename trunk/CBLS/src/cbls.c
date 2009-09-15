#include <stdio.h>
#include <sys/types.h>
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

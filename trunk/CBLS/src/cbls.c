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

	SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_sock < 0) {
		printf("socket() failed");
		exit(1);
	}

	SOCKADDR_IN saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(9367);

	int r = bind(listen_sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if(r < 0) {
		printf("bind() failed");
		exit(1);
	}

	if(listen(listen_sock, 5) < 0) {
		printf("listen() failed");
		exit(1);
	}

	printf("cbls version %s started", cbls_version);

#if defined(__WIN32__)
	WSACleanup();
#endif
	return 0;
}

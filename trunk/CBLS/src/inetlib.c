/*
 * inetlib.c
 *
 *  Created on: Sep 18, 2009
 *      Author: Scott
 */

#include "inetlib.h"
#include "sys_types.h"

void
inaddr2str (char abuf[HOSTLEN+1], struct SOCKADDR_IN *sa)
{
#ifdef CONFIG_IPV6
	inet_ntop(AFINET, (char *)&sa->SIN_ADDR, abuf, HOSTLEN+1);
#else
	inet_ntoa_r(sa->SIN_ADDR, abuf, 16);
#endif
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

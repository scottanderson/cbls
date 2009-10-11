/*
 * cbls_timer.h
 *
 *  Created on: Oct 8, 2009
 *      Author: Scott
 */

#ifndef CBLS_TIMER_H_
#define CBLS_TIMER_H_

#include "sys_net.h"
#include "sys_deps.h"
#include "sys_types.h"

struct timer {
	struct timer *next;
	struct timeval add_tv;
	struct timeval tv;
	int (*fn)();
	void *ptr;
	u_int8_t expire;
};

extern struct timer *timer_list;

void timer_delete_ptr (void *ptr);
void timer_add_secs (time_t secs, int (*fn)(), void *ptr);
time_t tv_secdiff (struct timeval *tv0, struct timeval *tv1);
void timer_check (struct timeval *before, struct timeval *after);

#endif /* CBLS_TIMER_H_ */

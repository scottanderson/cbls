/*
 * timer.c
 *
 *  Created on: Oct 8, 2009
 *      Author: Scott
 */

#include "cbls_timer.h"
#include "xmalloc.h"

struct timer *timer_list = 0;

void
timer_add (struct timeval *tv, int (*fn)(), void *ptr)
{
	struct timer *timer, *timerp;

	timer = xmalloc(sizeof(struct timer));
	timer->add_tv = *tv;
	timer->tv = *tv;
	timer->fn = fn;
	timer->ptr = ptr;

	timer->expire = 0;

	if (!timer_list || (timer_list->tv.tv_sec > timer->tv.tv_sec
			    || (timer_list->tv.tv_sec == timer->tv.tv_sec && timer_list->tv.tv_usec > timer->tv.tv_usec))) {
		timer->next = timer_list;
		timer_list = timer;
		return;
	}
	for (timerp = timer_list; timerp; timerp = timerp->next) {
		if (!timerp->next || (timerp->next->tv.tv_sec > timer->tv.tv_sec
				      || (timerp->next->tv.tv_sec == timer->tv.tv_sec && timerp->next->tv.tv_usec > timer->tv.tv_usec))) {
			timer->next = timerp->next;
			timerp->next = timer;
			return;
		}
	}
}

void
timer_delete_ptr (void *ptr)
{
	struct timer *timerp, *next;

	if (!timer_list)
		return;
	while (timer_list->ptr == ptr) {
		next = timer_list->next;
		xfree(timer_list);
		timer_list = next;
		if (!timer_list)
			return;
	}
	for (timerp = timer_list; timerp->next; timerp = next) {
		next = timerp->next;
		if (next->ptr == ptr) {
			next = timerp->next->next;
			xfree(timerp->next);
			timerp->next = next;
			next = timerp;
		}
	}
}

void
timer_add_secs (time_t secs, int (*fn)(), void *ptr)
{
	struct timeval tv;
	tv.tv_sec = secs;
	tv.tv_usec = 0;
	timer_add(&tv, fn, ptr);
}

time_t
tv_secdiff (struct timeval *tv0, struct timeval *tv1)
{
	time_t ts;

	ts = tv1->tv_sec - tv0->tv_sec;
	if (tv1->tv_usec > tv0->tv_usec) {
		ts += 1;
		if (tv1->tv_usec - tv0->tv_usec >= 500000)
			ts += 1;
	} else if (tv0->tv_usec - tv1->tv_usec > 500000) {
		ts -= 1;
	}

	return ts;
}

void
timer_check (struct timeval *before, struct timeval *after)
{
	struct timer *timer, *next, *prev;
	time_t secdiff, usecdiff;

	secdiff = after->tv_sec - before->tv_sec;
	if (before->tv_usec > after->tv_usec) {
		secdiff--;
		usecdiff = 1000000 - (before->tv_usec - after->tv_usec);
	} else {
		usecdiff = after->tv_usec - before->tv_usec;
	}
	for (timer = timer_list; timer; timer = timer->next) {
		if (secdiff > timer->tv.tv_sec
		    || (secdiff == timer->tv.tv_sec && usecdiff >= timer->tv.tv_usec)) {
			timer->expire = 1;
			timer->tv.tv_sec = timer->add_tv.tv_sec
					 - (secdiff - timer->tv.tv_sec);
			if (usecdiff > (timer->tv.tv_usec + timer->add_tv.tv_usec)) {
				timer->tv.tv_sec -= 1;
				timer->tv.tv_usec = 1000000 - timer->add_tv.tv_usec
						  + timer->tv.tv_usec - usecdiff;
			} else {
				timer->tv.tv_usec = timer->add_tv.tv_usec
						  + timer->tv.tv_usec - usecdiff;
			}
		} else {
			timer->tv.tv_sec -= secdiff;
			if (usecdiff > timer->tv.tv_usec) {
				timer->tv.tv_sec -= 1;
				timer->tv.tv_usec = 1000000 - (usecdiff - timer->tv.tv_usec);
			} else
				timer->tv.tv_usec -= usecdiff;
		}
	}

	prev = 0;
	for (timer = timer_list; timer; timer = next) {
		next = timer->next;
		if (timer->expire) {
			int keep;
			int (*fn)() = timer->fn, *ptr = timer->ptr;

			if (prev)
				prev->next = next;
			if (timer == timer_list)
				timer_list = next;
			keep = fn(ptr);
			if (keep)
				timer_add(&timer->add_tv, fn, ptr);
			xfree(timer);
			next = timer_list;
		} else {
			prev = timer;
		}
	}
}

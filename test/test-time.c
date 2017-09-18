/*
 * Copyright (c) 2002-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "event2/event-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#endif
#include <errno.h>

#include "event2/event.h"
#include "event2/event_compat.h"
#include "event2/event_struct.h"
#include "util-internal.h"

int called = 0;

#define NEVENT	20000

struct event *ev[NEVENT];

struct evutil_weakrand_state weakrand_state;

static int
rand_int(int n)
{
	return evutil_weakrand_(&weakrand_state) % n;
}

static void
time_cb(evutil_socket_t fd, short event, void *arg)
{
	struct timeval tv;
	int i, j;

	called++;

	if (called < 10*NEVENT) {
		for (i = 0; i < 10; i++) {
			j = rand_int(NEVENT);
			tv.tv_sec = 0;
			tv.tv_usec = rand_int(50000);
			if (tv.tv_usec % 2 || called < NEVENT)
				evtimer_add(ev[j], &tv);
			else
				evtimer_del(ev[j]);
		}
	}
}

int
main(int argc, char **argv)
{
	struct timeval tv;
	int i;
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);

	(void) WSAStartup(wVersionRequested, &wsaData);
#endif

	evutil_weakrand_seed_(&weakrand_state, 0);
	int cnt = 0;
	for(i = 0;i<100000;i++){
		ev_int32_t rand = evutil_weakrand_range_(&weakrand_state,10);
		if(rand == 0){
			cnt++;
		}
	}
	printf("cnt=%d cnt/100000.0=%f\n",cnt,cnt/100000.0);

	char *lua = "numid=28584376;areaid=1;nickname='dzMan16';vipid=0;right=0;charm=0;family=0;contribution=0;score=0;rich=144656200;dou=144656200;exp=11;win=29;lose=23;draw=3;escape=0;typescore=144656200;robot=0;netspeed=0;ganyu=0;ip='192.168.138.32';todayrich=2500000;clienttype=2;hardwareflag=0;picid=0;seat=0;osver=0;dw=0;gametime=20;elimited=0;todayallrich=2500000;monthrich=0;monthallrich=0;newplay=0;bankrich=0;ctype=0;";
	//char *lua = "todayrich=2500000;numid=28584376;areaid=1;nickname='dzMan16';vipid=0;right=0;charm=0;family=0;contribution=0;score=0;rich=144656200;dou=144656200;exp=11;win=29;lose=23;draw=3;escape=0;typescore=144656200;robot=0;netspeed=0;ganyu=0;ip='192.168.138.32';clienttype=2;hardwareflag=0;picid=0;seat=0;osver=0;dw=0;gametime=20;elimited=0;todayallrich=2500000;monthrich=0;monthallrich=0;newplay=0;bankrich=0;ctype=0;";
	int64_t v;
	char* plua = strstr(lua,"todayrich");
	int ret = sscanf(plua,"todayrich=%lld;",&v);
	printf("ret = %d v=%lld\n",ret,v);
	printf("sizeof(double)=%zu\n",sizeof(double));
	printf("short(100)=%hhd\n",(short)65536);


	/* Initalize the event library */
	event_init();

	for (i = 0; i < NEVENT; i++) {
		ev[i] = malloc(sizeof(struct event));

		/* Initalize one event */
		evtimer_set(ev[i], time_cb, ev[i]);
		tv.tv_sec = 0;
		tv.tv_usec = rand_int(50000);
		evtimer_add(ev[i], &tv);
	}

	event_dispatch();


	printf("%d, %d\n", called, NEVENT);
	return (called < NEVENT);
}


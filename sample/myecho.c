/*
  This example code shows how to write an (optionally encrypting) SSL proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <event2/tree.h>
#include <event2/queue.h>



#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "event-internal.h"
#include "util-internal.h"
#include "mm-internal.h"
#include "evthread-internal.h"




#include "sqlite3.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "zookeeper.h"

#include <getopt.h>


static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct evconnlistener *listener;
static char* zk_addr;
static char* listen_addr;
static struct bufferevent *zk_client;
static char buff[1024];



static sqlite3* db = NULL;

static lua_State *L = NULL;

static int callback(void *bev, int argc, char **argv, char **azColName){
   struct evbuffer* dst = bufferevent_get_output(bev);
   int i;
   char buff[1024];
   for(i=0; i<argc; i++){
   	  int len = snprintf(buff,sizeof(buff),"%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      //printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      evbuffer_add(dst,buff,len);
   }
   //printf("\n");
   return 0;
}



static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *src,*dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	size_t n_read_out;
	char buff[len+1];
	memset(buff,0,sizeof(buff));
	evbuffer_copyout(src,buff,len);
	fprintf(stdout,"readcb buff=%s len=%d\n",buff,len);
	
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_CRLF);
	if(NULL != line){
		printf("%s\n",line);
		char *errmsg = NULL;
		int rc = sqlite3_exec(db,line,callback,bev,&errmsg);
		if( rc != SQLITE_OK ){
		   fprintf(stderr, "SQL error: %s\n", errmsg);
		   sqlite3_free(errmsg);
		}
		free(line);
	}
	evbuffer_drain(src, len);
}



static void
eventcb(struct bufferevent *bev, short what, void *ctx){
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		bufferevent_free(bev);
	}
}


static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p){
	struct bufferevent *b_in;
	b_in = bufferevent_socket_new(base, fd,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}

static void
signal_cb(evutil_socket_t fd, short event, void *arg){

	struct event_base *base = arg;
	struct timeval delay = { 2, 0 };
	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
	event_base_loopexit(base, &delay);	
}


static struct bufferevent * 
connect_to_server(char* ipport,bufferevent_data_cb preadcb, bufferevent_event_cb peventcb){
	struct sockaddr_storage ss;
	int sl = sizeof(ss);
	if (evutil_parse_sockaddr_port(ipport,(struct sockaddr*)&ss, &sl) <0) {
		printf("can't parse  %s\n",ipport);
		return NULL;
	}
	
	struct bufferevent * client = bufferevent_socket_new(base, -1,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if(-1 == bufferevent_socket_connect(client,(struct sockaddr*)&ss,sl)){
		printf("can't connect %s\n",ipport);
		return NULL;
	}
	
	bufferevent_setcb(client, preadcb, NULL, peventcb, NULL);
	bufferevent_enable(client, EV_READ|EV_WRITE);
	evutil_socket_t fd = bufferevent_getfd(client);
	printf("fd=%d\n",fd);
	return client;
}


void 
zk_readcb(struct bufferevent *bev, void *ctx){


}


void 
zk_eventcb(struct bufferevent *bev, short what, void *ctx){
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close what = %d\n",what);
		bufferevent_free(bev);
	}
}

void 
evtimercb(evutil_socket_t fd, short what, void * arg){
	printf("evtimercb\n");
	zk_client = connect_to_server(zk_addr,zk_readcb,zk_eventcb);
	struct evbuffer* zk_out = bufferevent_get_output(zk_client);
	int len = snprintf(buff,sizeof(buff),"create -d %s\r\n",listen_addr);
	evbuffer_add(zk_out,buff,len+1);
}



int
main(int argc, char **argv)
{
	int i,socklen,ret,c;
	
	struct bufferevent * timer_event;
	
	setbuf(stdout,NULL);

	while(-1 != (c = getopt(argc,argv,"l:z:"))){
		switch(c){
		case 'l':
			listen_addr = strdup(optarg);
			break;
		case 'z':
			zk_addr = strdup(optarg);
			break;
		default:
			printf("error param\n");
			exit(1);
		}
	}


	L = lua_open();
	luaL_openlibs(L);
	


	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}

	
	sqlite3_initialize();
	
	sqlite3_open("test.db",&db);
	//sqlite3_open(":memory:",&db);
	
	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(listen_addr,
					(struct sockaddr*)&listen_on_addr, &socklen)<0){
		printf("Couldn't parse address %s\n",listen_addr);
		return 1;
	}
	

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);


	if (! listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}



	timer_event = evtimer_new(base, evtimercb, NULL);
	struct timeval tv = {5,0};
	evtimer_add(timer_event, &tv);

	

	/* Initalize one event */
	struct event * signal_int = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(signal_int, NULL);
	
	event_base_dispatch(base);	
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

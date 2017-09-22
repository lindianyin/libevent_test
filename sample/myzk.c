#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

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

#include "sqlite3.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <unistd.h>
#include <signal.h>




#define MAX_NODE (1024)

struct zknode{
	char path[256];
	int  watch[MAX_NODE];
	int  ctime;
	char data[1024];
};



static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct evconnlistener *listener;
static sqlite3* db = NULL;
static lua_State *L = NULL;
static char* progname;

static struct zknode* nodelist[MAX_NODE];


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
	struct evbuffer *src;
	size_t len;
	int c;
	char *p;
	int argc_ = 0;
	char *argv_[20];
	char *path = NULL;
	int watch = 0;
	char *cmd;
	int i;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	size_t n_read_out;
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_CRLF);

	
	if(line && strlen(line)>0){
		memset(argv_,0,sizeof(argv_));
		p = strtok(line," ");
		while(p && argc_ < 20){
			fprintf(stdout,"p=%s\n",p);
			argv_[argc_++] = strdup(p);
			p = strtok(NULL," ");
		}

		for(i = 0;i<argc_;i++){
			if(0 == strcmp("-w",argv_[i])){
				watch = 1;
			}else if(0 == strcmp("-p",argv_[i]) && i < (argc_-1)){
				path = strdup(argv_[i+1]);	
			}
		}
		cmd = strdup(argv_[0]);
		
	}

	fprintf(stdout,"cmd=%s path=%s watch=%d\n",cmd,path,watch);
	

	printf("-->%s\n",line);
	free(line);
	//if(NULL != line){
	//	printf("%s\n",line);
	//	char *errmsg = NULL;
	//	int rc = sqlite3_exec(db,line,callback,bev,&errmsg);
	//	if( rc != SQLITE_OK ){
	//	   fprintf(stderr, "SQL error: %s\n", errmsg);
	//	   sqlite3_free(errmsg);
	//	}
	//	free(line);
	//}
	//dst = bufferevent_get_output(bev);
	//evbuffer_add_buffer(dst, src);
	//evbuffer_drain(src, len);
}



static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		bufferevent_free(bev);
	}
}

static void
usage(){
	fprintf(stderr,"usage: %s -l 0.0.0.0:2311\n",progname);
	exit(1);
}



static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_in;
	char client_addr[256];
	evutil_format_sockaddr_port_(a,client_addr,sizeof(client_addr));
	fprintf(stdout,"client_addr is %s fd %d\n",client_addr,fd);

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

int
main(int argc, char **argv)
{
	int socklen;
	char *listen_addr;
	int c;

	setbuf(stdout,NULL);

	progname = strdup(argv[0]);


	while ((c = getopt(argc, argv, "l:h")) != -1) {
		switch (c) {
		case 'l':
			listen_addr = strdup(optarg);
			break;
		case 'h':
			usage();
			break;
		default:
			fprintf(stderr,"Illegal argument \"%c\"\n",c);
			usage();
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
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		fprintf(stderr,"Couldn't parse socket address_port\n");
	}

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (!listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}

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

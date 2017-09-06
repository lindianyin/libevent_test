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
#include <event2/thread.h>

#include "event-internal.h"
#include "util-internal.h"
#include "mm-internal.h"
#include "evthread-internal.h"



#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <getopt.h>

#include <string.h>



#include "sqlite3.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"


#include "zookeeper.h"

#define __LOG_DEBUG_ (0)
#define __LOG_WARN_  (1)
#define __LOG_MSG_   (2)
#define __LOG_ERROR_ (3)

#define __LOG__(level,fmt,...)\
	do{\
		char* flags[] = {"debug","warn","msg","error"};\
		char buff[1024];\
		time_t tnow = time(NULL);\
		struct tm* tmm = localtime(&tnow);\
		struct timeval tv;\
		gettimeofday(&tv,NULL);\
		int len = evutil_snprintf(buff,sizeof(buff),\
			"%04d-%02d-%02d %02d:%02d:%02d.%03ld %5s %20s +%-5d%-10s",\
			tmm->tm_year+1900,tmm->tm_mon+1,tmm->tm_mday,tmm->tm_hour,tmm->tm_min,tmm->tm_sec,tv.tv_usec/1000,flags[level],__FILE__ ,__LINE__,__FUNCTION__);\
		len = evutil_snprintf(buff+len,(sizeof(buff))- len,fmt,__VA_ARGS__);\
		fprintf(stderr,buff);\
		fprintf(stderr,"\n");\
	}while(0);





static struct event_base *base;
struct evconnlistener *listener;
static struct sockaddr_storage listen_on_addr;

static char* listen_addr;
static char* zk_addr;


#define MAX_NODE (1024)
static struct bufferevent *lst[MAX_NODE];
static char* lst_path[MAX_NODE];



static struct evutil_weakrand_state wr;

#define MAX_CLIENT (1024)
static struct bufferevent* clst[MAX_CLIENT];



static sqlite3* db = NULL;
	
static lua_State* L = NULL;


static zhandle_t *zh = NULL;
static clientid_t myid;
static const char *clientIdFile = 0;


static char* root_path = "/zk_test";

static const char* state2String(int state){
  if (state == 0)
    return "CLOSED_STATE";
  if (state == ZOO_CONNECTING_STATE)
    return "CONNECTING_STATE";
  if (state == ZOO_ASSOCIATING_STATE)
    return "ASSOCIATING_STATE";
  if (state == ZOO_CONNECTED_STATE)
    return "CONNECTED_STATE";
  if (state == ZOO_EXPIRED_SESSION_STATE)
    return "EXPIRED_SESSION_STATE";
  if (state == ZOO_AUTH_FAILED_STATE)
    return "AUTH_FAILED_STATE";

  return "INVALID_STATE";
}

static const char* type2String(int state){
  if (state == ZOO_CREATED_EVENT)
    return "CREATED_EVENT";
  if (state == ZOO_DELETED_EVENT)
    return "DELETED_EVENT";
  if (state == ZOO_CHANGED_EVENT)
    return "CHANGED_EVENT";
  if (state == ZOO_CHILD_EVENT)
    return "CHILD_EVENT";
  if (state == ZOO_SESSION_EVENT)
    return "SESSION_EVENT";
  if (state == ZOO_NOTWATCHING_EVENT)
    return "NOTWATCHING_EVENT";

  return "UNKNOWN_EVENT_TYPE";
}
static void
eventcb_r(struct bufferevent *bev, short what, void *ctx);
static void
readcb_r(struct bufferevent *bev, void *ctx);


void strings_completion_t_(int rc,
        const struct String_vector *strings, const void *data){
    printf("strings_completion_t_ strings=%p;data=%p;strings->count=%d;\n",strings,data,strings->count);
	int i,len;
	char buff[256];
	char buffer[1024];
	buffer[0] = '\0';
	int  buffer_len= sizeof(buffer);
	struct Stat stat;
	(void)buffer_len;
	for(i=0;i<strings->count;i++){
		printf("child_path=%s\n",(strings->data)[i]);
		len = snprintf(buff,sizeof(buff),"%s/%s",root_path,(strings->data)[i]);
		assert(len < sizeof(buff));
		rc = zoo_get(zh,buff,1,buffer,&buffer_len,&stat);
		fprintf(stderr,"buffer=%s\n",buffer);
		//rc = zoo_exists(zh,buff,1,&stat);
		if(ZOK != rc){
			fprintf(stderr,"Error rc=%d\n",rc);
		}

		//connect to server
		//connect to server
		struct sockaddr_storage ss;
		int sl = sizeof(ss);
		if (evutil_parse_sockaddr_port(
					buffer,(struct sockaddr*)&ss, &sl) <0) {
			printf("can't parse  %s\n",buffer);
			return;
		}
		
		struct bufferevent * b_out = bufferevent_socket_new(base, -1,
		    	BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		if(-1 == bufferevent_socket_connect(b_out,(struct sockaddr*)&ss,sl)){
			printf("can't connect %s\n",buffer);
			return;
		}
		
		bufferevent_setcb(b_out, readcb_r, NULL, eventcb_r, NULL);
		bufferevent_enable(b_out, EV_READ|EV_WRITE);
		evutil_socket_t fd = bufferevent_getfd(b_out);
		lst[fd] = b_out;
		lst_path[fd] = strdup(buffer);
		fprintf(stderr, "fd =%u \n", fd);

		
	}
}

void strings_completion_t_1(int rc,
        const struct String_vector *strings, const void *data){
    printf("strings_completion_t_ strings=%p;data=%p;strings->count=%d;\n",strings,data,strings->count);
	int i,len;
	char buff[256];
	char buffer[1024];
	int  buffer_len= sizeof(buffer);
	struct Stat stat;
	(void)buffer_len;
	for(i=0;i<strings->count;i++){
		printf("child_path=%s\n",(strings->data)[i]);
		len = snprintf(buff,sizeof(buff),"%s/%s",root_path,(strings->data)[i]);
		assert(len < sizeof(buff));
		rc = zoo_get(zh,buff,1,buffer,&buffer_len,&stat);
		//rc = zoo_exists(zh,buff,1,&stat);
		if(ZOK != rc){
			fprintf(stderr,"Error rc=%d\n",rc);
		}
	}
}



static void
readcb_r(struct bufferevent *bev, void *ctx);

static void
eventcb_r(struct bufferevent *bev, short what, void *ctx);



void watcher(zhandle_t *zzh, int type, int state, const char *path,
             void* context)
{
    /* Be careful using zh here rather than zzh - as this may be mt code
     * the client lib may call the watcher before zookeeper_init returns */
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
    fprintf(stderr, "Watcher %s state = %s", type2String(type), state2String(state));
    if (path && strlen(path) > 0) {
      fprintf(stderr, " for path %s", path);
    }
    fprintf(stderr, "\n");

	struct Stat stat;
	zoo_exists(zh,path,1,&stat);

	printf("watcher thread tid = %lx\n", EVTHREAD_GET_ID());  
	
	
	if(ZOO_CREATED_EVENT == type 
		&& ZOO_CONNECTED_STATE == state){
		//int rc = zoo_aget_children(zh,path,1,strings_completion_t_,NULL);
		int buffer_len = 1024*1024;
		char *buffer = malloc(buffer_len);
		buffer[0] = '\0';
		struct Stat stat;
		int rc = zoo_get(zh, path, 0, buffer,   
						   	&buffer_len, &stat);
		fprintf(stderr, "buffer=%s \n", buffer);

		//connect to server
		struct sockaddr_storage ss;
		int sl = sizeof(ss);
		if (evutil_parse_sockaddr_port(
					buffer,(struct sockaddr*)&ss, &sl) <0) {
			printf("can't parse  %s\n",buffer);
			//return;
			free(buffer);
			goto out;
		}
		
		struct bufferevent * b_out = bufferevent_socket_new(base, -1,
		    	BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		if(-1 == bufferevent_socket_connect(b_out,(struct sockaddr*)&ss,sl)){
			printf("can't connect %s\n",buffer);
			//return;
			free(buffer);
			goto out;
		}
		
		bufferevent_setcb(b_out, readcb_r, NULL, eventcb_r, NULL);
		bufferevent_enable(b_out, EV_READ|EV_WRITE);
		evutil_socket_t fd = bufferevent_getfd(b_out);
		lst[fd] = b_out;
		lst_path[fd] = strdup(path);
		fprintf(stderr, "fd =%u \n", fd);
		

		if(ZOK != rc){
			 fprintf(stderr, "Error %d \n", rc);
		}
	}else if(ZOO_DELETED_EVENT == type 
		&& ZOO_CONNECTED_STATE == state){
		fprintf(stderr, "delete \n");
		int i;
		for(i = 0;i<1024;i++){
			if(lst_path[i] && 0 == strcmp(lst_path[i],path)){
				fprintf(stderr, "lst_path[i]=%s \n",lst_path[i]);
				int fd = i;
				struct bufferevent * ev = lst[fd];
				if(NULL != ev){
					bufferevent_free(ev);
					//evutil_closesocket(fd);
					lst[fd] = NULL;
					free(lst_path[fd]);
					lst_path[fd] = NULL;
					fprintf(stderr, "close fd =%u \n", fd);
				}
			}

		}
	}
	//EVBASE_RELEASE_LOCK(base, th_base_lock);


    if (type == ZOO_SESSION_EVENT) {
        if (state == ZOO_CONNECTED_STATE) {
            const clientid_t *id = zoo_client_id(zzh);
            if (myid.client_id == 0 || myid.client_id != id->client_id) {
                myid = *id;
                fprintf(stderr, "Got a new session id: 0x%llx\n",
                        (long long) myid.client_id);
                if (clientIdFile) {
                    FILE *fh = fopen(clientIdFile, "w");
                    if (!fh) {
                        perror(clientIdFile);
                    } else {
                        int rc = fwrite(&myid, sizeof(myid), 1, fh);
                        if (rc != sizeof(myid)) {
                            perror("writing client id");
                        }
                        fclose(fh);
                    }
                }
            }
        } else if (state == ZOO_AUTH_FAILED_STATE) {
            fprintf(stderr, "Authentication failure. Shutting down...\n");
            zookeeper_close(zzh);
            //shutdownThisThing=1;
            zh=0;
        } else if (state == ZOO_EXPIRED_SESSION_STATE) {
            fprintf(stderr, "Session expired. Shutting down...\n");
            //zookeeper_close(zzh);
           // shutdownThisThing=1;
            zh=0;
        }
    }
out:
	EVBASE_RELEASE_LOCK(base,th_base_lock);
}




static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);


static void
readcb(struct bufferevent *bev, void *ctx)
{
	printf("readcb\n");
	struct evbuffer *src,*dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	char buff[len];
	evbuffer_copyout(src,buff,len);
	
	size_t n_read_out = 0;
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_LF);
	if(NULL != line && n_read_out > 0){
		printf("%s\n",line);
		//char *errmsg = NULL;
		//int rc = sqlite3_exec(db,line,callback,bev,&errmsg);
		//if( rc != SQLITE_OK ){
		 //  fprintf(stderr, "SQL error: %s\n", errmsg);
		//   sqlite3_free(errmsg);
		//}
		//ev_int32_t _idx = evutil_weakrand_range_(&wr,1);
		ev_int32_t _idx = rand() % MAX_NODE;
		struct bufferevent *rst[MAX_NODE];
		int rst_idx = 0;
		int i;
		for(i=0;i< MAX_NODE; i++){
			if(lst[i]){
				rst[rst_idx++] = lst[i];
			}
		}
		int _ridx = rand() % rst_idx;
		int _len = n_read_out + 100;
		char *_pbuff =	mm_calloc(1,_len);
		int _rlen = snprintf(_pbuff,_len,"%s\n",line);
		assert(_rlen < _len);
		dst = bufferevent_get_output(rst[_ridx]);
		int _ret = evbuffer_add(dst,line,_len);
		printf("_idx=%d _ridx=%d n_read_out=%d _ret=%d\n",_idx,_ridx,n_read_out,_ret);
		mm_free(line);
		mm_free(_pbuff);



	}
	//dst = bufferevent_get_output(bev);
	//evbuffer_add_buffer(dst, src);
	//evbuffer_drain(src, len);
}


static void
readcb_r(struct bufferevent *bev, void *ctx)
{
	//printf("readcb_r\n");
	struct evbuffer *src,*dst;
	size_t len;
	int i;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	char *buff = mm_malloc(len);
	evbuffer_copyout(src,buff,len);
	int c = 0;
	for(i = 0; i < 1024 ;i++){
		if(clst[i]){
			dst = bufferevent_get_output(clst[i]);
			//printf("readcb_r add buff\n");
			evbuffer_add(dst, buff,len);
			c++;
		}
	}
	printf("c=%d\n",c);
	//evbuffer_add_buffer(dst, src);
	evbuffer_drain(src, len);
	mm_free(buff);
}






static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	printf("eventcb\n");
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		bufferevent_free(bev);
	}
}


static void
eventcb_r(struct bufferevent *bev, short what, void *ctx)
{
	printf("eventcb_r what=%d\n",(int)what);
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		//evutil_socket_t fd = bufferevent_getfd(bev);
		//assert(fd > -1);
		//clst[fd] = NULL;		
		//bufferevent_free(bev);
	}
}


static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fputs("   echo <listen-on-addr>\n", stderr);
	fputs("Example:\n", stderr);
	fputs("   echo 127.0.0.1:8888\n", stderr);

	exit(1);
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_in;
	/* Create two linked bufferevent objects: one to connect, one for the
	 * new connection */
	b_in = bufferevent_socket_new(base, fd,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	clst[fd] = b_in;

	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}



int main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;

	

	if (argc < 2)
		syntax();

	setbuf(stdout,NULL);

	//bin/srs -l 0.0.0.0:8888 -z 192.168.135.57:2181
	int c = 0;
	while ((c = getopt(argc, argv, "l:z:")) != -1) {
		switch (c) {
		case 'l':
			listen_addr = strdup(optarg);
			break;
		case 'z':
			zk_addr = strdup(optarg);
			break;
		default:
			__LOG__(__LOG_ERROR_,"Illegal argument \"%c\" ",c);
			exit(1);
		}
	}

	base = event_base_new();
	if (!base) {
		__LOG__(__LOG_ERROR_,"%s",event_base_new());
		return 1;
	}

	
	//lua
	L = lua_open();
	luaL_openlibs(L);


	//zookeeper
	//zoo_set_debug_level(ZOO_LOG_LEVEL_DEBUG);
	zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);
	zh = zookeeper_init(zk_addr, watcher, 30000, &myid, 0, 0);
	int rc = 0;
	struct Stat stat;
	rc = zoo_exists(zh,root_path,0,&stat);
	if(ZNONODE == rc){
		rc = zoo_create(zh,root_path,NULL,-1,&ZOO_OPEN_ACL_UNSAFE,0,0,0);
		if(ZOK != rc){
			 fprintf(stderr, "Error %d \n", rc);
		}
	}
	
	//watch root node
	rc = zoo_aget_children(zh,root_path,1,strings_completion_t_,NULL);
	if(ZOK != rc){
		 fprintf(stderr, "Error %d \n", rc);
	}

	//exists watch child node.
	for(i = 0;i<1024;i++){
		char buff[256];
		int len = snprintf(buff,sizeof(buff),"%s/%d",root_path,i);
		assert(len < sizeof(buff));
		rc = zoo_exists(zh,buff,1,&stat);
		assert(ZOK == rc || ZNONODE == rc);
	}


	sqlite3_initialize();

	__LOG__(__LOG_DEBUG_,"%s","sqlite3_initialize");
	
	sqlite3_open("test.db",&db);
	//sqlite3_open(":memory:",&db);
	
	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(
			listen_addr,(struct sockaddr*)&listen_on_addr, &socklen) <0) {
		return 0;
	}
	evthread_use_pthreads();
	
	evutil_weakrand_seed_(&wr,0);
	srand(time(NULL)^getpid());


	__LOG__(__LOG_MSG_,"main thread tid = 0x%x\n", pthread_self());  

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (!listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}
	
	
	event_base_dispatch(base);
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

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


static struct event_base *base;
static struct sockaddr_storage listen_on_addr;

static const char* root_path = "/zk_test";
static zhandle_t *zh = NULL;
static clientid_t myid;
static const char *clientIdFile = 0;


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


void strings_completion_t_(int rc,
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


void watcher(zhandle_t *zzh, int type, int state, const char *path,
             void* context)
{
    /* Be careful using zh here rather than zzh - as this may be mt code
     * the client lib may call the watcher before zookeeper_init returns */
	//EVBASE_ACQUIRE_LOCK(base, th_base_lock);
    fprintf(stderr, "Watcher %s state = %s", type2String(type), state2String(state));
    if (path && strlen(path) > 0) {
      fprintf(stderr, " for path %s", path);
    }
    fprintf(stderr, "\n");
/*
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
					evutil_closesocket(fd);
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
	*/
}


static sqlite3* db = NULL;

static lua_State *L = NULL;

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

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
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_ANY);
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
	//dst = bufferevent_get_output(bev);
	//evbuffer_add_buffer(dst, src);
	evbuffer_drain(src, len);
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
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		bufferevent_free(bev);
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

	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}

static void
signal_cb(evutil_socket_t fd, short event, void *arg)
{
	//struct event *signal = arg;
	//printf("%s: got signal %d\n", __func__, event_get_signal(signal));
	//zookeeper_close(zh);
	//exit(0);

	struct event_base *base = arg;
	struct timeval delay = { 2, 0 };

	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");

	event_base_loopexit(base, &delay);
	
}



struct node{
	int key;
	int value;
	SPLAY_ENTRY(node) link;
};


int comp(struct node *a,struct node *b){
	return a->key - b->key;
}

SPLAY_HEAD(head, node) root = SPLAY_INITIALIZER();
SPLAY_PROTOTYPE(head, node, link, comp);

SPLAY_GENERATE(head, node, link, comp); 

#include "../ht-internal.h"

struct htnode{
	int key;
	int value;
	HT_ENTRY(htnode) node;
};
HT_HEAD(hthead, htnode) htroot =  HT_INITIALIZER();     

static inline unsigned
hash_htnode(const struct htnode *e)
{
	/* We need to do this silliness to convince compilers that we
	 * honestly mean to cast e->ptr to an integer, and discard any
	 * part of it that doesn't fit in an unsigned.
	 */
	unsigned u = (unsigned) ((ev_uintptr_t) e->key);
	/* Our hashtable implementation is pretty sensitive to low bits,
	 * and every struct event is over 64 bytes in size, so we can
	 * just say >>6. */
	return (u >> 6);
}

static inline int
eq_htnode(const struct htnode *a,
    const struct htnode *b)
{
	return a->key == b->key;
}



HT_PROTOTYPE(hthead, htnode, node, hash_htnode,
    eq_htnode)
HT_GENERATE(hthead, htnode, node, hash_htnode,
    eq_htnode, 0.5, malloc, realloc, free)

//slist
struct slist_node{
	SLIST_ENTRY(slist_node) slist_nodes;
	int val;
};

SLIST_HEAD(slist_head,slist_node);

//list
struct list_node{
	LIST_ENTRY(list_node) list_nodes;
	int val;
};

LIST_HEAD(list_head,list_node);





int
main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;

	struct evconnlistener *listener;


	{
		//SLIST_INIT(slist);
		struct slist_head  slhead = SLIST_HEAD_INITIALIZER(slhead);
		SLIST_INIT(&slhead);
		struct slist_node *p = malloc(sizeof(struct slist_node));
		p->val = 1;
		SLIST_INSERT_HEAD(&slhead,p,slist_nodes);
		struct slist_node *p1 = malloc(sizeof(struct slist_node));
		p1->val = 2;
		SLIST_INSERT_HEAD(&slhead,p1,slist_nodes);

		struct slist_node *var = NULL;
		SLIST_FOREACH(var, &slhead, slist_nodes){
			printf("val1=%d\n",var->val);
		}

	}

	{
		struct list_head lhead = LIST_HEAD_INITIALIZER(list_head);
		LIST_INIT(&lhead);
		struct list_node *p = malloc(sizeof(struct list_node));
		p->val = 10;
		struct list_node *p1 = malloc(sizeof(struct list_node));
		p1->val = 20;
		struct list_node *p2 = malloc(sizeof(struct list_node));
		p2->val = 10;		
		LIST_INSERT_HEAD(&lhead,p,list_nodes);
		LIST_INSERT_HEAD(&lhead,p1,list_nodes);
		LIST_INSERT_HEAD(&lhead,p2,list_nodes);
		struct list_node *var = NULL;
		LIST_FOREACH(var,&lhead,list_nodes){
			printf("val2_befor=%d\n",var->val);
		}
		
		for(var = LIST_FIRST(&lhead); var != LIST_END(lhead);){
			if(10 == var->val){
				LIST_REMOVE(var,list_nodes);
				var = LIST_NEXT(var,list_nodes);
				free(var);
				continue;
			}else{
				var = LIST_NEXT(var,list_nodes);
			}
		}

		LIST_FOREACH(var,&lhead,list_nodes){
			printf("val2_after=%d\n",var->val);
		}

	}


	{

	





	}
	


	{
		//SLIST_INIT(slist);
		struct slist_head  slhead = SLIST_HEAD_INITIALIZER(slhead);
		SLIST_INIT(&slhead);
		struct slist_node *p = malloc(sizeof(struct slist_node));
		p->val = 1;
		SLIST_INSERT_HEAD(&slhead,p,slist_nodes);
		struct slist_node *p1 = malloc(sizeof(struct slist_node));
		p1->val = 2;
		SLIST_INSERT_HEAD(&slhead,p1,slist_nodes);

		struct slist_node *var = NULL;
		SLIST_FOREACH(var, &slhead, slist_nodes){
			printf("val=%d\n",var->val);
		}

	}
	

	if (argc < 2)
		syntax();

	struct node *p = malloc(sizeof(struct node));
	p->key = 1;
	p->value = 11;

	struct node * retp = SPLAY_INSERT(head, &root, p);
	//printf("%p\n",retp);

	struct node *p1 = malloc(sizeof(struct node));
	p1->key = 2;
	p1->value = 12;

	retp = SPLAY_INSERT(head, &root, p1);
	//printf("%p\n",retp);


	struct node tmp;
	tmp.key = 1;

	struct node* tmpnode =  SPLAY_FIND(head,&root,&tmp);
	if(NULL != tmpnode){
		//printf("%d = %d\n",tmpnode->key,tmpnode->value);
	}
	SPLAY_REMOVE(head,&root,&tmp);
	free(tmpnode);

	struct node* px = NULL;
	SPLAY_FOREACH(px,head,&root){
		//printf("%d = %d\n",px->key,px->value);
	}

	struct htnode* p2 = malloc(sizeof(struct htnode));
	p2->key = 11;
	p2->value = 111;
	HT_INSERT(hthead,&htroot,p2);
	
	struct htnode* p3 = malloc(sizeof(struct htnode));
	p3->key = 22;
	p3->value = 222;
	HT_INSERT(hthead,&htroot,p3);
	

	struct htnode httmpnode;
	httmpnode.key = 22;
	struct htnode *p4 = HT_FIND(hthead,&htroot,&httmpnode);
	
	//printf("p4->value=%d\n",p4->value);
	HT_REMOVE(hthead,&htroot,&httmpnode);
	free(p4);
	unsigned size = HT_SIZE(&htroot);
	//printf("%u\n",size);

	//exit(0);

	setbuf(stdout,NULL);

	L = lua_open();
	luaL_openlibs(L);

	evthread_use_pthreads();//this must be called first befor any other libevent funtion
	assert(1 == EVTHREAD_LOCKING_ENABLED());

	


	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}


	//zookeeper
	//zoo_set_debug_level(ZOO_LOG_LEVEL_DEBUG);
	zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);
	zh = zookeeper_init("192.168.135.57:2181", watcher, 30000, &myid, 0, 0);
	int rc = 0;
	int node = atoi(argv[2]);
	const char* ipport = argv[1];
	int ipport_len = strlen(ipport);
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
	(void)ipport_len;
	(void)node;
	if(ZOK != rc){
		 fprintf(stderr, "Error %d \n", rc);
	}
	
	
	sqlite3_initialize();
	
	sqlite3_open("test.db",&db);
	//sqlite3_open(":memory:",&db);
	
	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(argv[1],
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		int p = atoi(argv[i]);
		struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
		if (p < 1 || p > 65535)
			syntax();
		sin->sin_port = htons(p);
		sin->sin_addr.s_addr = htonl(0x7f000001);
		sin->sin_family = AF_INET;
		socklen = sizeof(struct sockaddr_in);
	}
	//evthread_use_pthreads();
	
	


	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);


	if (! listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}

   //create zookeeper node
	char mynode[256];
    int len = snprintf(mynode,sizeof(mynode),"%s/%d",root_path,node);
	assert(len < sizeof(mynode));
	rc = zoo_create(zh,mynode,ipport,ipport_len,&ZOO_OPEN_ACL_UNSAFE,ZOO_EPHEMERAL,0,0);
	if(ZOK != rc){
		 fprintf(stderr, "Error %d \n", rc);
	}



	/* Initalize one event */
	struct event * signal_int = evsignal_new(base, SIGINT, signal_cb, base);

	event_add(signal_int, NULL);


	
	event_base_dispatch(base);

	EVBASE_ACQUIRE_LOCK(base,th_base_lock);
	zookeeper_close(zh);
	EVBASE_RELEASE_LOCK(base,th_base_lock);	


	
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

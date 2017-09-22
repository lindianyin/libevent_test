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

#include <event2/queue.h>


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
			"%04d-%02d-%02d %02d:%02d:%02d.%03ld %x %5s %20s +%-5d%-15s",\
			tmm->tm_year+1900,tmm->tm_mon+1,tmm->tm_mday,tmm->tm_hour,tmm->tm_min,tmm->tm_sec,tv.tv_usec/1000,EVTHREAD_GET_ID(),flags[level],__FILE__ ,__LINE__,__FUNCTION__);\
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

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	__LOG__(__LOG_MSG_,"strings_completion_t_ strings=%p;data=%p;strings->count=%d;",strings,data,strings->count);
	
	int i,len;
	char buff[256];
	char buffer[1024];
	memset(buffer,0,sizeof(buffer));
	int  buffer_len= sizeof(buffer);
	struct Stat stat;
	(void)buffer_len;
	for(i=0;i<strings->count;i++){
		__LOG__(__LOG_MSG_,"child_path=%s",(strings->data)[i]);
		len = snprintf(buff,sizeof(buff),"%s/%s",root_path,(strings->data)[i]);
		assert(len < sizeof(buff));
		rc = zoo_get(zh,buff,1,buffer,&buffer_len,&stat);
		__LOG__(__LOG_MSG_,"buffer=%s",buffer);
		//rc = zoo_exists(zh,buff,1,&stat);
		if(ZOK != rc){
			__LOG__(__LOG_MSG_,"Error rc=%d",rc);
		}

		//connect to server
		struct sockaddr_storage ss;
		int sl = sizeof(ss);
		if (evutil_parse_sockaddr_port(
					buffer,(struct sockaddr*)&ss, &sl) <0) {
			__LOG__(__LOG_ERROR_,"can't parse  %s",buffer);
			continue;
		}
		
		struct bufferevent * b_out = bufferevent_socket_new(base, -1,
		    	BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		if(-1 == bufferevent_socket_connect(b_out,(struct sockaddr*)&ss,sl)){
			__LOG__(__LOG_ERROR_,"can't connect %s",buffer);
			continue;
		}
		
		bufferevent_setcb(b_out, readcb_r, NULL, eventcb_r, NULL);
		bufferevent_enable(b_out, EV_READ|EV_WRITE);
		evutil_socket_t fd = bufferevent_getfd(b_out);
		lst[fd] = b_out;
		lst_path[fd] = strdup(buffer);
		__LOG__(__LOG_MSG_,"fd =%u", fd);
		
	}

	EVBASE_RELEASE_LOCK(base, th_base_lock);	
}

void strings_completion_t_1(int rc,
        const struct String_vector *strings, const void *data){
    printf("strings_completion_t_ strings=%p;data=%p;strings->count=%d;",strings,data,strings->count);
	int i,len;
	char buff[256];
	char buffer[1024];
	int  buffer_len= sizeof(buffer);
	struct Stat stat;
	(void)buffer_len;
	for(i=0;i<strings->count;i++){
		printf("child_path=%s",(strings->data)[i]);
		len = snprintf(buff,sizeof(buff),"%s/%s",root_path,(strings->data)[i]);
		assert(len < sizeof(buff));
		rc = zoo_get(zh,buff,1,buffer,&buffer_len,&stat);
		//rc = zoo_exists(zh,buff,1,&stat);
		if(ZOK != rc){
			fprintf(stderr,"Error rc=%d",rc);
		}
	}
}



static void
readcb_r(struct bufferevent *bev, void *ctx);

static void
eventcb_r(struct bufferevent *bev, short what, void *ctx);


struct watch_st{
	zhandle_t *zzh;
	int type;
	int status;
	const char* path;
	void* context;
};

//list
struct queue_node{
	SIMPLEQ_ENTRY(list_node) queue_nodes;
	struct watch_st *val;
};

SIMPLEQ_HEAD(queue_head,queue_node);


void* qlock = NULL;

struct queue_head watchqueue = LIST_HEAD_INITIALIZER(queue_head);

void my_stat_completion(int rc, const struct Stat *stat, const void *data);

void watcher_1(zhandle_t *zzh, int type, int state, const char *path,
             void* context)
{
	__LOG__(__LOG_MSG_,"watcher_1 %s state = %s", type2String(type), state2String(state));
	EVLOCK_LOCK(qlock,0);

    if (path && strlen(path) > 0) {
	 	 __LOG__(__LOG_MSG_,"for path %s", path);
		struct queue_node * pn = mm_calloc(1,sizeof(*pn));
		struct watch_st * pw = mm_calloc(1,sizeof(*pw));
		pw->zzh = zzh;
		pw->type = type;
		pw->status = state;
		pw->context = context;
		pw->path = strdup(path);
		pn->val = pw;

		SIMPLEQ_INSERT_TAIL(&watchqueue,pn,queue_nodes);
		
		

	}else{
		__LOG__(__LOG_ERROR_,"watcher_1 %s state = %s", type2String(type), state2String(state));
	}

	EVLOCK_UNLOCK(qlock,0);
	return;
}





void watcher(zhandle_t *zzh, int type, int state, const char *path,
             void* context)
{
	//EVLOCK_LOCK(qlock,0);	
	//struct queue_node * pn = mm_malloc(sizeof(*pn));
	//struct watch_st * pw = mm_malloc(sizeof(*pw));
	//pw->zzh = zzh;
	//pw->type = type;
	//pw->status = strdup(path);
	//pw->context = context;
	//pn->val = pw;

	//SIMPLEQ_INSERT_TAIL(&watchqueue,pn,queue_nodes);

	//struct Stat stat1;
	//zoo_exists(zh,path,1,&stat1);

	//EVLOCK_UNLOCK(qlock,0);
	//return;

	zoo_aexists(zh, path, 1, my_stat_completion, strdup(path));

    /* Be careful using zh here rather than zzh - as this may be mt code
     * the client lib may call the watcher before zookeeper_init returns */
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	__LOG__(__LOG_MSG_,"Watcher %s state = %s", type2String(type), state2String(state));
    if (path && strlen(path) > 0) {
      //fprintf(stderr, " for path %s", path);
	  __LOG__(__LOG_MSG_,"for path %s", path);
    }
    //fprintf(stderr, "\n");
	//return;
	//struct Stat stat;
	//zoo_exists(zh,path,1,&stat);
 
	 __LOG__(__LOG_MSG_,"watcher thread tid = %lx", EVTHREAD_GET_ID());
	
	if(ZOO_CREATED_EVENT == type 
		&& ZOO_CONNECTED_STATE == state){
		//int rc = zoo_aget_children(zh,path,1,strings_completion_t_,NULL);
		int buffer_len = 1024*1024;
		char *buffer = malloc(buffer_len);
		buffer[0] = '\0';
		struct Stat stat;
		int rc = zoo_get(zh, path, 1, buffer,   
						   	&buffer_len, &stat);
		__LOG__(__LOG_MSG_,"buffer=%s ", buffer);

	
		//connect to server
		struct sockaddr_storage ss;
		int sl = sizeof(ss);
		if (evutil_parse_sockaddr_port(
					buffer,(struct sockaddr*)&ss, &sl) <0) {
			__LOG__(__LOG_ERROR_,"can't parse  %s",buffer);
			//return;
			free(buffer);
			goto out;
		}
		
		struct bufferevent * b_out = bufferevent_socket_new(base, -1,
		    	BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		if(-1 == bufferevent_socket_connect(b_out,(struct sockaddr*)&ss,sl)){
			__LOG__(__LOG_ERROR_,"can't connect %s",buffer);
			//return;
			free(buffer);
			goto out;
		}
		
		bufferevent_setcb(b_out, readcb_r, NULL, eventcb_r, NULL);
		bufferevent_enable(b_out, EV_READ|EV_WRITE);
		evutil_socket_t fd = bufferevent_getfd(b_out);
		lst[fd] = b_out;
		lst_path[fd] = strdup(path);
		__LOG__(__LOG_MSG_,"fd =%u", fd);

		if(ZOK != rc){
			 __LOG__(__LOG_ERROR_,"Error %d", rc);
		}

		
	}else if(ZOO_DELETED_EVENT == type 
		&& ZOO_CONNECTED_STATE == state){
		 __LOG__(__LOG_ERROR_,"%s", "delete");
		int i;
		for(i = 0;i<1024;i++){
			if(lst_path[i] && 0 == strcmp(lst_path[i],path)){
				 __LOG__(__LOG_ERROR_,"lst_path[i]=%s",lst_path[i]);
				int fd = i;
				struct bufferevent * ev = lst[fd];
				if(NULL != ev){
					bufferevent_free(ev);
					//evutil_closesocket(fd);
					lst[fd] = NULL;
					free(lst_path[fd]);
					lst_path[fd] = NULL;
					fprintf(stderr, "close fd =%u", fd);
					 __LOG__(__LOG_ERROR_,"close fd =%u", fd);
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
				 __LOG__(__LOG_MSG_,"Got a new session id: 0x%llx",
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
            fprintf(stderr, "Authentication failure. Shutting down...");
            zookeeper_close(zzh);
            //shutdownThisThing=1;
            zh=0;
        } else if (state == ZOO_EXPIRED_SESSION_STATE) {
            fprintf(stderr, "Session expired. Shutting down...");
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
	__LOG__(__LOG_MSG_,"ctx=%p",ctx);
	struct evbuffer *src,*dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	char buff[len];
	evbuffer_copyout(src,buff,len);
	
	size_t n_read_out = 0;
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_LF);
	if(NULL != line && n_read_out > 0){
		__LOG__(__LOG_MSG_,"%s",line);
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
		if(rst_idx > 0){
			int _ridx = rand() % rst_idx;
			int _len = n_read_out + 100;
			char *_pbuff =	mm_calloc(1,_len);
			int _rlen = snprintf(_pbuff,_len,"%s\n",line);
			assert(_rlen < _len);
			dst = bufferevent_get_output(rst[_ridx]);
			int _ret = evbuffer_add(dst,line,_len);
			__LOG__(__LOG_MSG_,"_idx=%d _ridx=%d n_read_out=%d _ret=%d",_idx,_ridx,n_read_out,_ret);
			//SSL_renegotiate(bufferevent_openssl_get_ssl(bev));

			mm_free(line);
			mm_free(_pbuff);
		}else{
			mm_free(line);
		}
		//evbuffer_add_printf( bufferevent_get_output(bev),"-->%s\n","world");
		
	


	}
	//dst = bufferevent_get_output(bev);
	//evbuffer_add_buffer(dst, src);
	//evbuffer_drain(src, len);
}


static void
readcb_r(struct bufferevent *bev, void *ctx)
{
	__LOG__(__LOG_MSG_,"ctx=%p",ctx);
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
	__LOG__(__LOG_MSG_,"c=%d",c);
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
	__LOG__(__LOG_MSG_,"eventcb watch=%d",(int)what);
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		__LOG__(__LOG_MSG_,"eventcb close watch=%d",(int)what);
		evutil_socket_t fd = bufferevent_getfd(bev);
		assert(fd > -1);
		clst[fd] = NULL;		
		bufferevent_free(bev);	
	}
}


static void
eventcb_r(struct bufferevent *bev, short what, void *ctx)
{
	__LOG__(__LOG_MSG_,"eventcb_r what=%d",(int)what);
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		__LOG__(__LOG_MSG_,"%s","eventcb close");
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

X509 *
ssl_getcert(void);

EVP_PKEY *
ssl_getkey(void);

SSL_CTX *
get_ssl_ctx(void);


static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_in;
	/* Create two linked bufferevent objects: one to connect, one for the
	 * new connection */
//	b_in = bufferevent_socket_new(base, fd,
//	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

	init_ssl();
    SSL *ssl;
    X509 *cert = ssl_getcert();
    EVP_PKEY *key = ssl_getkey();
    ssl = SSL_new(get_ssl_ctx());
	SSL_use_certificate(ssl, ssl_getcert());
	SSL_use_PrivateKey(ssl, ssl_getkey());

	
	
	b_in = bufferevent_openssl_socket_new(
            base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE|BEV_OPT_DEFER_CALLBACKS);	
	
	clst[fd] = b_in;

	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>


static const char KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKibTEzXjj+sqpipePX1lEk5BNFuL/dDBbw8QCXgaJWikOiKHeJq\n"
    "3FQ0OmCnmpkdsPFE4x3ojYmmdgE2i0dJwq0CAwEAAQJAZ08gpUS+qE1IClps/2gG\n"
    "AAer6Bc31K2AaiIQvCSQcH440cp062QtWMC3V5sEoWmdLsbAHFH26/9ZHn5zAflp\n"
    "gQIhANWOx/UYeR8HD0WREU5kcuSzgzNLwUErHLzxP7U6aojpAiEAyh2H35CjN/P7\n"
    "NhcZ4QYw3PeUWpqgJnaE/4i80BSYkSUCIQDLHFhLYLJZ80HwHTADif/ISn9/Ow6b\n"
    "p6BWh3DbMar/eQIgBPS6azH5vpp983KXkNv9AL4VZi9ac/b+BeINdzC6GP0CIDmB\n"
    "U6GFEQTZ3IfuiVabG5pummdC4DNbcdI+WKrSFNmQ\n"
    "-----END RSA PRIVATE KEY-----\n";

EVP_PKEY *
ssl_getkey(void)
{
	EVP_PKEY *key;
	BIO *bio;

	/* new read-only BIO backed by KEY. */
	bio = BIO_new_mem_buf((char*)KEY, -1);
	assert(bio);

	key = PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
	BIO_free(bio);
	assert(key);
	return key;
}

X509 *
ssl_getcert(void)
{
	/* Dummy code to make a quick-and-dirty valid certificate with
	   OpenSSL.  Don't copy this code into your own program! It does a
	   number of things in a stupid and insecure way. */
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	EVP_PKEY *key = ssl_getkey();
	int nid;
	time_t now = time(NULL);

	assert(key);

	x509 = X509_new();
	assert(x509);
	assert(0 != X509_set_version(x509, 2));
	assert(0 != ASN1_INTEGER_set(X509_get_serialNumber(x509),
		(long)now));

	name = X509_NAME_new();
	assert(name);
	nid = OBJ_txt2nid("commonName");
	assert(NID_undef != nid);
	assert(0 != X509_NAME_add_entry_by_NID(
		    name, nid, MBSTRING_ASC, (unsigned char*)"example.com",
		    -1, -1, 0));

	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);

	X509_time_adj(X509_get_notBefore(x509), 0, &now);
	now += 3600;
	X509_time_adj(X509_get_notAfter(x509), 0, &now);
	X509_set_pubkey(x509, key);
	assert(0 != X509_sign(x509, key, EVP_sha1()));

	return x509;
}

static int disable_tls_11_and_12 = 0;
static SSL_CTX *the_ssl_ctx = NULL;

SSL_CTX *
get_ssl_ctx(void)
{
	if (the_ssl_ctx)
		return the_ssl_ctx;
	the_ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!the_ssl_ctx)
		return NULL;
	if (disable_tls_11_and_12) {
#ifdef SSL_OP_NO_TLSv1_2
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_1
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif
	}
	return the_ssl_ctx;
}

void
init_ssl(void)
{
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	assert(SSLeay() == OPENSSL_VERSION_NUMBER);
}

void dumpStat(const struct Stat *stat) {
    char tctimes[40];
    char tmtimes[40];
    time_t tctime;
    time_t tmtime;

    if (!stat) {
        fprintf(stderr,"null\n");
        return;
    }
    tctime = stat->ctime/1000;
    tmtime = stat->mtime/1000;
       
    ctime_r(&tmtime, tmtimes);
    ctime_r(&tctime, tctimes);
       
    fprintf(stderr, "\tctime = %s\tczxid=%llx\n"
    "\tmtime=%s\tmzxid=%llx\n"
    "\tversion=%x\taversion=%x\n"
    "\tephemeralOwner = %llx\n",
     tctimes, stat->czxid, tmtimes,
    stat->mzxid,
    (unsigned int)stat->version, (unsigned int)stat->aversion,stat->ephemeralOwner);
}



void my_stat_completion(int rc, const struct Stat *stat, const void *data) {
    fprintf(stderr, "%s: rc = %d Stat:\n", (char*)data, rc);
    dumpStat(stat);
    free((void*)data);
    //if(batchMode)
    //  shutdownThisThing=1;
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

	evthread_use_pthreads();//this must be called first befor any other libevent funtion
	//evthread_enable_lock_debugging();
	assert(1 == EVTHREAD_LOCKING_ENABLED());

	//openssl
	//init_ssl();
	
	EVTHREAD_ALLOC_LOCK(qlock,EVTHREAD_LOCKTYPE_RECURSIVE);
	assert(qlock);

	SIMPLEQ_INIT(&watchqueue);

	


	base = event_base_new();
	if (!base) {
		__LOG__(__LOG_ERROR_,"%s","event_base_new()");
		return 1;
	}

	
	//lua
	L = lua_open();
	luaL_openlibs(L);


	//zookeeper
	//zoo_set_debug_level(ZOO_LOG_LEVEL_DEBUG);
	zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);
	zh = zookeeper_init(zk_addr, watcher_1, 30000, &myid, 0, 0);



	int rc = 0;
	struct Stat stat;
	rc = zoo_exists(zh,root_path,0,&stat);
	if(ZNONODE == rc){
		rc = zoo_create(zh,root_path,NULL,-1,&ZOO_OPEN_ACL_UNSAFE,0,0,0);
		if(ZOK != rc){
			 __LOG__(__LOG_ERROR_,"Error %d ",rc);
		}
	}
	
	//watch root node
	rc = zoo_aget_children(zh,root_path,1,strings_completion_t_,NULL);
	if(ZOK != rc){
		 __LOG__(__LOG_ERROR_,"Error %d ",rc);		 
	}

	//exists watch child node.
	for(i = 0;i<10;i++){
		char buff[256];
		int len = snprintf(buff,sizeof(buff),"%s/%d",root_path,i);
		assert(len < sizeof(buff));
		//rc = zoo_exists(zh,buff,1,&stat);
		zoo_aexists(zh, buff, 1, my_stat_completion, strdup(buff));
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
	
	
	evutil_weakrand_seed_(&wr,0);
	srand(time(NULL)^getpid());


	__LOG__(__LOG_MSG_,"main thread tid = 0x%x", pthread_self());  

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (!listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}

	while(1){
		event_base_loop(base,EVLOOP_ONCE | EVLOOP_NONBLOCK);

		if(EVLOCK_TRY_LOCK_(qlock)){
			if(!SIMPLEQ_EMPTY(&watchqueue)){
				struct queue_node * pnode = SIMPLEQ_FIRST(&watchqueue);
				__LOG__(__LOG_MSG_,"path=%s", pnode->val->path); 
				watcher(pnode->val->zzh,pnode->val->type,pnode->val->status,pnode->val->path,pnode->val->context);
				mm_free(pnode->val->path);
				mm_free(pnode->val);
				mm_free(pnode);
				
				SIMPLEQ_REMOVE_HEAD(&watchqueue,pnode,queue_nodes);
			}
			EVLOCK_UNLOCK(qlock,0);		
		}
	}

	//event_base_dispatch(base);
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

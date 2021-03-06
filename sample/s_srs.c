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
static struct bufferevent * zk_client;


#define MAX_NODE (1024)
static struct bufferevent *lst[MAX_NODE];


static struct evutil_weakrand_state wr;

#define MAX_CLIENT (1024)
static struct bufferevent* clst[MAX_CLIENT];



static sqlite3* db = NULL;
	
static lua_State* L = NULL;


static struct bufferevent * 
connect_to_server(char* ipport,bufferevent_data_cb readcb, bufferevent_event_cb eventcb);

static void
readcb(struct bufferevent *bev, void *ctx);


static void
readcb_r(struct bufferevent *bev, void *ctx);


static void
eventcb_r(struct bufferevent *bev, short what, void *ctx);



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
	char* line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_ANY);
	if(NULL != line && n_read_out > 0){
		__LOG__(__LOG_MSG_,"line=%s n_read_out=%d",line,n_read_out);
		struct bufferevent *rst[MAX_NODE];
		int rst_idx = 0;
		int i;
		for(i=0;i< MAX_NODE; i++){
			if(lst[i]){
				rst[rst_idx++] = lst[i];
			}
		}
		__LOG__(__LOG_MSG_,"rst_idx=%d",rst_idx);
		if(rst_idx > 0){
			int _ridx = rand() % rst_idx;
			dst = bufferevent_get_output(rst[_ridx]);
			assert(dst);
			int _len = n_read_out + 100;
			char *_pbuff =	mm_calloc(1,_len);
			int _rlen = snprintf(_pbuff,_len,"%s\r\n",line);
			assert(_rlen < _len);
				
			int _ret = evbuffer_add(dst,_pbuff,_rlen+1);
			__LOG__(__LOG_MSG_,"_ridx=%d n_read_out=%d _ret=%d",_ridx,n_read_out,_ret);
			
			mm_free(line);
			mm_free(_pbuff);
		}else{
			mm_free(line);
		}

	}

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
zk_readcb(struct bufferevent *bev, void *ctx){
	struct evbuffer * zk_input = bufferevent_get_input(bev);
	char *line = NULL;
	size_t n_read_out = 0;
	int i = 0;
	char* lines[256];
	int lines_offset = 0;
	while(line = evbuffer_readln(zk_input, &n_read_out,EVBUFFER_EOL_CRLF)){
		printf("zk_readcb line=%s n_read_out=%d\n",line,n_read_out);
		lines[lines_offset++] = line;
		if(0 == strcmp(line,"") && n_read_out == 0){
			assert(lines_offset == 4);
			if(0 == strncmp(lines[1], "get",3)
				|| 0 == strncmp(lines[1],"create",6)){
				//connect to gs
				struct bufferevent * server_client = connect_to_server(lines[2],readcb_r,eventcb_r);
				if(server_client){
					evutil_socket_t fd =  bufferevent_getfd(server_client);
					printf("connect to server fd=%d\n",fd);
					lst[fd] = server_client;
				}else{
					printf("can't connect to server %s\n",lines[2]);
				}

			}

			for(i = 0;i<lines_offset;i++){
				free(lines[i]);
			}
			lines_offset = 0;
			break;
		}
	}
}


static void
zk_eventcb(struct bufferevent *bev, short what, void *ctx){
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		evutil_socket_t fd = bufferevent_getfd(bev);
		printf("eventcb close fd=%d\n",fd);
		lst[fd] = NULL;
		bufferevent_free(bev);
	}	

}


static struct bufferevent * 
connect_to_server(char* ipport,bufferevent_data_cb readcb, bufferevent_event_cb eventcb){
	struct sockaddr_storage ss;
	int sl = sizeof(ss);
	if (evutil_parse_sockaddr_port(ipport,(struct sockaddr*)&ss, &sl) <0) {
		__LOG__(__LOG_ERROR_,"can't parse  %s",ipport);
		return NULL;
	}
	
	struct bufferevent * client = bufferevent_socket_new(base, -1,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if(-1 == bufferevent_socket_connect(client,(struct sockaddr*)&ss,sl)){
		__LOG__(__LOG_ERROR_,"can't connect %s",ipport);
		return NULL;
	}
	
	bufferevent_setcb(client, readcb, NULL, eventcb, NULL);
	bufferevent_enable(client, EV_READ|EV_WRITE);
	evutil_socket_t fd = bufferevent_getfd(client);
	__LOG__(__LOG_DEBUG_,"fd=%d",fd);
	return client;
}



static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	__LOG__(__LOG_MSG_,"eventcb watch=%d",(int)what);
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		evutil_socket_t fd = bufferevent_getfd(bev);
		__LOG__(__LOG_MSG_,"eventcb close what=%d fd=%d",(int)what,fd);
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
		evutil_socket_t fd = bufferevent_getfd(bev);
		__LOG__(__LOG_MSG_,"%s fd=%d","eventcb close",fd);
		clst[fd] = NULL;		
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
	init_ssl();
    SSL *ssl;
    X509 *cert = ssl_getcert();
    EVP_PKEY *key = ssl_getkey();
    ssl = SSL_new(get_ssl_ctx());
	SSL_use_certificate(ssl, ssl_getcert());
	SSL_use_PrivateKey(ssl, ssl_getkey());
		
	b_in = bufferevent_openssl_socket_new(
            base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);	
	
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


void 
evtimercb(evutil_socket_t fd, short what, void * arg){
	printf("evtimercb\n");
	//connect to myzk
	zk_client = connect_to_server(zk_addr,zk_readcb,zk_eventcb);
	assert(zk_client);

	struct evbuffer * zk_output = bufferevent_get_output(zk_client);
	char buff[1024];
	int len = snprintf(buff,sizeof(buff),"get\r\n");
	assert(len < sizeof(buff));
	evbuffer_add(zk_output,buff,len+1);

}




int main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;
	int len;
	struct bufferevent * timer_event;

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

	event_enable_debug_mode();


	base = event_base_new();
	if (!base) {
		__LOG__(__LOG_ERROR_,"%s","event_base_new()");
		return 1;
	}

	
	//lua
	L = lua_open();
	luaL_openlibs(L);

		
	sqlite3_initialize();

	__LOG__(__LOG_DEBUG_,"%s","sqlite3_initialize");
	
	sqlite3_open("test.db",&db);
	//sqlite3_open(":memory:",&db);
	
	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(
			listen_addr,(struct sockaddr*)&listen_on_addr, &socklen) <0) {
		return 1;
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


	timer_event = evtimer_new(base, evtimercb, NULL);
	struct timeval tv = {5,0};
	evtimer_add(timer_event, &tv);






	event_base_dispatch(base);
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

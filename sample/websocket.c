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


#include <uuid/uuid.h>


#include <openssl/sha.h>
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h> 


static int base64_encode(unsigned char *str,int str_len,char *encode,int *encode_len);
static int base64_decode(const char* input, int inLen, unsigned char* output, int *outLen);



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
   printf("callback argc=%d\n",argc);
   struct evbuffer* dst = bufferevent_get_output(bev);
   int i;
   char buff[1024];
   char sendbuff[1024];
   int sendbuff_len = 1024;
   for(i=0; i<argc; i++){
   		int len = snprintf(buff,sizeof(buff),"%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      //printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      //evbuffer_add(dst,buff,len);
		char sendbuff[1024];
		int sendbuff_len = 1024;
		buildFrame(buff,strlen(buff),sendbuff,&sendbuff_len);
		evbuffer_add(dst,sendbuff,sendbuff_len);  
   }
   //printf("\n");
   return 0;
}

struct ws_frame{
	unsigned int fin:1;
	unsigned int rsv1:1;
	unsigned int rsv2:1;
	unsigned int rsv3:1;
	unsigned int opcode:4;
	unsigned int masked:1;
	unsigned int payload_len:7;
}__attribute__ ((packed));


uint64_t revert_64(uint64_t p){
	char buff[8];
	int i;
	int idx = 0;
	for(i = 7;i>=0;i--){
		buff[idx++] = ((char*)&p)[i];
	}
	return *(uint64_t*)buff;
}

void buildFrame(char* buff,int len,char* buff_out,int *len_out){
	int pos = 0;
	buff_out[pos] = (unsigned char)(1 << 7);//fin
	buff_out[pos] = buff_out[pos] | 0x1;//text frame
	printf("buff_out[pos]=%02x\n",buff_out[pos]&0xFFu);
	pos++;
	buff_out[pos] = 0;//(unsigned char)(1 << 7);//mask
	//buff_out[pos] =(unsigned char)(1 << 7);//mask
	printf("buff_out[pos]=%02x\n",buff_out[pos]&0xFFu);
	if(len < 126){
		buff_out[pos] = buff_out[pos] | len;
		pos++;
	}else if (len >= 126 && len <= UINT16_MAX){
		buff_out[pos] = 126;
		pos++;
		*(uint16_t*)&(buff_out[pos]) = ntohs(len);
		pos += 2;
	}else{
		buff_out[pos] = 127;
		pos++;
		*(uint64_t*)&(buff_out[pos]) = revert_64((uint64_t)len);
		pos += 8;
	}
	//uint32_t masking_key = rand();
	//*(uint32_t *)&buff_out[pos] = masking_key;
	//pos += 4;
	int idx;
	for(idx = 0;idx<len;idx++){
		buff_out[pos+idx] = buff[idx];// ^ ((char *)&masking_key)[idx % 4];
		//buff_out[pos+idx] = buff[idx] ^ ((char *)&masking_key)[idx % 4];
	}
	pos += len;
	*len_out = pos;
}




static void
readcb_frame(struct bufferevent *bev, void *ctx){
	printf("%s\n","readcb_frame");
	struct evbuffer* src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if(len < 3){
		printf("error len = %d\n",(int)len);
		return;
	}
	
	printf("len=%d\n",(int)len);
	char buff[len];
	evbuffer_copyout(src,buff,len);
	//evbuffer_remove(src,buff,len);


	int pos = 0;
	unsigned char fin = (unsigned char)buff[pos] >> 7;
	unsigned char opcode = (unsigned char)buff[pos] & 0x0f;

	if(opcode == 0x8){
		bufferevent_free(bev);
		printf("close socekt\n");
		return;
	}

	pos++;
	unsigned char mask = (unsigned char)buff[pos] >> 7;
	unsigned char payload_length = (unsigned char)buff[pos] &0x7f;
	pos++;
	if(payload_length == 126){
		if(pos + 2 > len){
			printf("error pos=%d\n",pos);
			return;
		}		
		uint16_t length = 0;
		memcpy(&length, buff + pos, 2);
		pos += 2;

		payload_length = ntohs(length);
	}
	else if(payload_length == 127){
		if(pos + 8 > len){
			printf("error pos=%d\n",pos);
			return;
		}		
		uint64_t length = 0;
		memcpy(&length, buff + pos, 8);		
		pos += 8;
		char buff[8];
		int i;
		int idx = 0;
		for(i = 7;i>=0;i--){
			buff[idx++] = ((char*)&length)[i];
		}
		//payload_length = ntohl(length);??
		payload_length = *(uint64_t*)buff;
	}
	printf("fin=%d opcode=%d mask=%d payload_length=%d\n",fin,opcode,mask,payload_length);
	if(mask){
		if(pos + 4 > len){
			printf("error pos=%d\n",pos);
			return;
		}		
		char masking_key[4];
		memcpy(masking_key,buff+pos,4);
		pos += 4;

		if(pos + payload_length > len){
			printf("error pos=%d\n",pos);
			return;
		}
		
		char buff_out[payload_length+1];//one postion for '\0'
		int i;
		for(i = 0;i<payload_length;i++){
			buff_out[i] = buff[pos+i] ^ masking_key[i%4];
		}
		pos += payload_length;

		if(pos > len){
			printf("error pos=%d\n",pos);
			return;
		}


		buff_out[payload_length] = '\0';
		printf("buff_out=%s\n",buff_out);

		char *errmsg = NULL;
		int rc = sqlite3_exec(db,buff_out,callback,bev,&errmsg);
		if( rc != SQLITE_OK ){
		   fprintf(stderr, "SQL error: %s\n", errmsg);
		   sqlite3_free(errmsg);
		}
		
			
	}

	evbuffer_drain(src,pos);

	//char sendbuff[1024];
	//int sendbuff_len = 1024;
	//char* sendstr = "worldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworldworld";
	
	//buildFrame(sendstr,strlen(sendstr),sendbuff,&sendbuff_len);
	//printf("sendbuff_len=%d\n",sendbuff_len);
	//struct evbuffer* dst = bufferevent_get_output(bev);
	//size_t len_out = evbuffer_get_length(dst);
	//printf("len_out=%d\n",len_out);
	//evbuffer_add(dst,sendbuff,sendbuff_len);
	//len_out = evbuffer_get_length(dst);
	//printf("len_out=%d\n",len_out);
	
}




static void
readcb(struct bufferevent *bev, void *ctx)
{

	struct evbuffer *src,*dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	size_t n_read_out;
	char* line = NULL;
	char* swk = NULL;
	while(line = evbuffer_readln(src,&n_read_out,EVBUFFER_EOL_CRLF)){
		printf("%s\n",line);

		if(0 == strncmp(line,"Sec-WebSocket-Key:",18)){
			char* p = strchr(line,':');
			while(*p== ':' || *p == ' '){
				p++;
			}
			swk = strdup(p);
		}
		mm_free(line);
	}
	//test uuid
	uuid_t uu;
	uuid_clear(uu);
	uuid_generate(uu);
	char buff[256];
	memset(buff,0,sizeof(buff));
	uuid_unparse_upper(uu,buff);
	printf("uuid=%s\n",buff);
	printf("swk=%s\n",swk);
	char swa[512];
	//snprintf(swa,sizeof(swa),"%s%s",swk,buff);
	snprintf(swa,sizeof(swa),"%s%s",swk,"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	printf("swa=%s\n",swa);

	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c,swa,strlen(swa));
	char md[SHA_DIGEST_LENGTH];
	SHA1_Final(md,&c);
	char encode[SHA_DIGEST_LENGTH*10];
	int encode_len = SHA_DIGEST_LENGTH*10;
	memset(encode,0,sizeof(encode));
	base64_encode(md,sizeof(md),encode,&encode_len);	
	printf("encode=%s encode_len=%d\n",encode,encode_len);

	char head[1024];
	snprintf(head,sizeof(head),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",encode);

	printf("head=%s\n",head);

	dst = bufferevent_get_output(bev);
	evbuffer_add(dst,head,strlen(head));//important!!! can't send '\0'
	
	mm_free(swk);		
	printf("len=%d\n",(int)evbuffer_get_length(src));
	bufferevent_setcb(bev, readcb_frame, NULL, eventcb, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	
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
	//int *cbarg = mm_malloc(sizeof(int));
	//*cbarg = 0;
	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}

static void
signal_cb(evutil_socket_t fd, short event, void *arg)
{
	struct event *signal = arg;

	printf("%s: got signal %d\n", __func__, event_get_signal(signal));
	zookeeper_close(zh);
	exit(0);
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





static int base64_encode(unsigned char *str,int str_len,char *encode,int *encode_len)  
{  
    BIO *bmem, *b64;  
    BUF_MEM *bptr;  
  
    if ( !str || !encode )  
    {  
        return 1;  
    }  
      
    b64 = BIO_new( BIO_f_base64() ); 
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
    bmem = BIO_new( BIO_s_mem() );  
    b64 = BIO_push( b64, bmem );  
    BIO_write( b64, str, str_len ); //encode  
    if ( BIO_flush( b64 ) );  
    BIO_get_mem_ptr( b64, &bptr );  
    if( bptr->length > *encode_len )  
    {  
        printf("encode_len too small\n");  
        return 1;   
    }     
    *encode_len = bptr->length;  
    memcpy( encode, bptr->data, bptr->length );  
//  write(1,encode,bptr->length);  
    BIO_free_all( b64 );  
    return 0;  
}  
  
static int base64_decode(const char* input, int inLen, unsigned char* output, int *outLen)  
{  
    if (!input || !output)  
    {  
        return -1;  
    }  
  
    char *psz_tmp = malloc( inLen + 1 );  
    if ( !psz_tmp )  
    {  
        abort();  
    }  
    memset( psz_tmp, 0, inLen + 1 );  
      
    psz_tmp[inLen] = '\n';      // Openssl demand to have '\n' to end the string.  
    memcpy(&psz_tmp[0], input, inLen);  
    memset(output, 0 , *outLen);  
    BIO * b642 = BIO_new(BIO_f_base64());
	BIO_set_flags(b642, BIO_FLAGS_BASE64_NO_NL);
    BIO * bmem2 = BIO_new_mem_buf(&psz_tmp[0], inLen+1);  
    // should not use the input directly, the follow is wrong  
    //BIO * bmem2 = BIO_new_mem_buf( ( char * )input, inLen+1);  
    bmem2 = BIO_push(b642, bmem2);  
    *outLen = BIO_read(bmem2, output, *outLen);  
    BIO_free_all(bmem2);  
    return 0;  
} 













int
main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;

	struct evconnlistener *listener;

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
	evthread_use_pthreads();
	
	


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
	struct event * signal_int = evsignal_new(base, SIGINT, signal_cb, event_self_cbarg());

	event_add(signal_int, NULL);


	
	event_base_dispatch(base);




	
	evconnlistener_free(listener);
	event_base_free(base);
	sqlite3_close(db);
	sqlite3_shutdown();	
	libevent_global_shutdown();
	
	return 0;
}

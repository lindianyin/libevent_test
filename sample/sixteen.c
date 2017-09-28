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


#include <uuid/uuid.h>


#include <openssl/sha.h>
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h> 


#include <getopt.h>


#include "cJSON.h"


enum command{
	c2s_login = 100,
	s2c_login,
	
};


enum error_code{
	ec_success,
};

struct user{
	int  id;
	char username[50];
	char passwd[50];
	char nickname[50];
	char head[50];
	int  money;
};

enum user_status{
	us_pre_login,
	us_logined,
};


struct conn_client{
	struct bufferevent* bev;
	struct user* usr;
	enum user_status us;
};

enum player_status{
	player_ready,

};

struct player{
	struct conn_client* conn_clt;
	enum player_status ps;
};

enum table_status{
	ts_ready,
	ts_beting,
};


struct table{
	struct player* postion[256];
	struct player* watch_postion[256];
};



//sql
const char* select_user_by_username = "select id,username,passwd,nickname,head,money from user where username = ?;";
const char* insert_user = "INSERT INTO user (id,username,passwd,nickname,head,money) VALUES (NULL,?,\"passwd\",\"nickname\",\"head\",1000);";


//global
static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct evconnlistener *listener;
static char* listen_addr;


static sqlite3* db = NULL;
static lua_State *L = NULL;

#define MAX_CLIENT (1024)

static struct conn_client* conn_clients[MAX_CLIENT];



//declare
static int callback(void *bev, int argc, char **argv, char **azColName);

void buildFrame(char* buff,int len,char* buff_out,int *len_out);

uint64_t revert_64(uint64_t p);

static void readcb_frame(struct bufferevent *bev, void *ctx);

static void
readcb(struct bufferevent *bev, void *ctx);

static void
eventcb(struct bufferevent *bev, short what, void *ctx);

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p);


static void
signal_cb(evutil_socket_t fd, short event, void *arg);


static int base64_encode(unsigned char *str,int str_len,char *encode,int *encode_len);
static int base64_decode(const char* input, int inLen, unsigned char* output, int *outLen);



void testjson();
void testsqlite();


int parse_request(char *req,int *cmd,cJSON** param);

int process_message(struct bufferevent *bev,char *msg,int len);

int process_login(struct bufferevent *bev,int cmd,cJSON *param);

int process_send(struct bufferevent *bev,char *buff,int len);

int send_param(struct bufferevent *bev,int cmd,cJSON* param,int ec);



int
main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;
	int c;
	setbuf(stdout,NULL);
	while(-1 != (c = getopt(argc,argv,"l:"))){
		switch(c){
		case 'l':
			listen_addr = strdup(optarg);
			break;
		default:
			fprintf(stderr,"invalid param\n");
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
	
	sqlite3_open("sixteen.db",&db);
	//sqlite3_open(":memory:",&db);

	testjson();



	
	
	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(listen_addr,
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		
		fprintf(stderr, "Couldn't parse %s\n",listen_addr);
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



//implement
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
		process_message(bev,buff_out,payload_length+1);

		
		//printf("buff_out=%s\n",buff_out);

		//char *errmsg = NULL;
		//int rc = sqlite3_exec(db,buff_out,callback,bev,&errmsg);
		//if( rc != SQLITE_OK ){
		//   fprintf(stderr, "SQL error: %s\n", errmsg);
		 //  sqlite3_free(errmsg);
		//}
		
			
	}

	evbuffer_drain(src,pos);
	
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
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		printf("eventcb close\n");
		evutil_socket_t fd = bufferevent_getfd(bev);
		struct conn_client *cc = conn_clients[fd];
		if(cc){
			free(cc->usr);
			free(cc);
			conn_clients[fd] = NULL;
		}
		
		bufferevent_free(bev);
	}
}



static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_in;
	b_in = bufferevent_socket_new(base, fd,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

	struct conn_client * pcc = calloc(sizeof(*pcc),1);
	struct user* pu = calloc(sizeof(*pu),1);
	pcc->bev = b_in;
	pcc->usr = pu;
	pcc->us = us_pre_login;
	conn_clients[fd] = pcc;
	
	bufferevent_setcb(b_in, readcb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);
}

static void
signal_cb(evutil_socket_t fd, short event, void *arg)
{
	struct event *signal = arg;
	printf("%s: got signal %d\n", __func__, event_get_signal(signal));
	exit(0);
}




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


void testparse(){
	char *request = "------->{\"cmd\":100,\"param\":[{\"action\":1},\"hello\",2]}";
	char *p = request + 8;
	fprintf(stdout,"p=%s\n",p);
	cJSON *root = cJSON_Parse(p);
	cJSON *cmd = cJSON_GetObjectItem(root,"cmd");
	fprintf(stdout,"cmd=%d\n",cmd->valueint);
	cJSON *param = cJSON_GetObjectItem(root,"param");
	int cnt = cJSON_GetArraySize(param);
	fprintf(stdout,"cnt=%d\n",cnt);
	int i = 0;
	for(i = 0;i<cnt;i++){
		cJSON * element = cJSON_GetArrayItem(param,i);
		cJSON * _item;
		if(element->type == cJSON_Object){
			_item = cJSON_GetObjectItem(element,"action");
			fprintf(stdout,"action=%d\n",_item->valueint);	
		}if(element->type == cJSON_String){
			fprintf(stdout,"%s\n",element->valuestring);
		}else if(element->type == cJSON_Number){
			fprintf(stdout,"%d\n",element->valueint);	
		}
	}

	cJSON_Delete(root);
}



void testjson(){
	testparse();
	char* request = "------->{\"cmd\":100,\"param\":[\"username\",\"passwd\"]}";
	int cmd = 0;
	cJSON *param = NULL;
	int ret = parse_request(request+8,&cmd,&param);
	if(!ret){
		fprintf(stderr,"can't parse request\n");
	}
	cJSON_Delete(param);

	testsqlite();

	
    cJSON *root = cJSON_CreateArray();
	cJSON_AddItemToArray(root, cJSON_CreateNumber(10));
	cJSON_AddItemToArray(root, cJSON_CreateString("hello"));	
	char * json = cJSON_Print(root);
	fprintf(stdout,"%s\n",json);

	cJSON * _root = cJSON_Parse(json);
	cJSON * element;
	cJSON_ArrayForEach(element, _root){
		if(element->type == cJSON_String){
			fprintf(stdout,"%s\n",element->valuestring);
		}else if(element->type == cJSON_Number){
			fprintf(stdout,"%f\n",element->valuedouble);	
		}
	}
	cJSON_Delete(_root);
	
	
	free(json);
	cJSON_Delete(root);
	
	
}


int parse_request(char *req,int *cmd,cJSON** param){
	cJSON *root = cJSON_Parse(req);
	cJSON *pc = NULL;
	cJSON *pp = NULL;
	if(!root){
		fprintf(stderr,"invalid json %s\n",req);
		cJSON_Delete(root);
		return 0;
	}
	if(root->type != cJSON_Object){
		fprintf(stderr,"json must be object %s\n",req);
		cJSON_Delete(root);
		return 0;		
	}
	
	pc = cJSON_GetObjectItem(root,"cmd");	
	if(!pc){
		fprintf(stderr,"can't parse cmd %s\n",req);
		cJSON_Delete(root);
		return 0;			
	}

	if(pc->type != cJSON_Number){
		fprintf(stderr,"cmd must be a number %s\n",req);
		cJSON_Delete(root);
		return 0;			
	}
	pp = cJSON_GetObjectItem(root,"param");

	if(!pp){
		fprintf(stderr,"can't parse param %s\n",req);
		cJSON_Delete(root);
		return 0;
	}
	if(pp->type != cJSON_Array){
		fprintf(stderr,"param must be array %s\n",req);
		cJSON_Delete(root);
		return 0;		
	}
	*cmd = pc->valueint;
	*param = cJSON_Duplicate(pp,1);
	cJSON_Delete(root);
	return 1;
}


void testsqlite(){
	{
		sqlite3_stmt * stmt = NULL; 
		const char *zTail;
		if (sqlite3_prepare_v2(db, 
           "SELECT id,username,passwd,nickname,head,money from user;", -1, &stmt, &zTail) == SQLITE_OK){       
   			 while( sqlite3_step(stmt) == SQLITE_ROW ) {
			 	int64_t id = sqlite3_column_int(stmt,0);
            	char* username = sqlite3_column_text( stmt, 1);
				char* passwd = sqlite3_column_text( stmt, 2); 
				char* nickname = sqlite3_column_text( stmt, 3);
				char* head = sqlite3_column_text( stmt, 4); 
				int   money = sqlite3_column_int( stmt, 5);
				//fprintf(stdout,"id = %lld username=%s passwd=%s nickname=%s head=%s money=%d\n",id,username,passwd,nickname,head,money);
   			 }
     	}else{
			fprintf(stderr,sqlite3_errmsg(db));

		}
		sqlite3_finalize(stmt); 
	}

	{
		sqlite3_stmt * stmt = NULL; 
		const char *zTail;
		//int ret;
		//ret = sqlite3_prepare_v2(db,select_user_by_username,-1,&stmt, &zTail);
		//if (ret != SQLITE_OK){
		//	fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
		//	return;
		//}
		//const char* username = "nickanme";
		//sqlite3_bind_text(stmt,1,username,-1,NULL);
		//ret = sqlite3_step(stmt);
		
		//fprintf(stdout,"ret=%d\n",ret);
		//sqlite3_finalize(stmt);
		
		if (sqlite3_prepare_v2(db, 
           select_user_by_username, -1, &stmt, &zTail) == SQLITE_OK){
           const char* username = "nickname";
			sqlite3_bind_text(stmt,1,username,strlen(username),SQLITE_STATIC);
   			 while(sqlite3_step(stmt) == SQLITE_ROW ) {
			 	int64_t id = sqlite3_column_int(stmt,0);
          		char* username = sqlite3_column_text( stmt, 1);
				char* passwd = sqlite3_column_text( stmt, 2); 
				char* nickname = sqlite3_column_text( stmt, 3);
				char* head = sqlite3_column_text( stmt, 4); 
				int   money = sqlite3_column_int( stmt, 5);
				fprintf(stdout,"id = %lld username=%s passwd=%s nickname=%s head=%s money=%d\n",id,username,passwd,nickname,head,money);
   			 }
     	}else{
     		fprintf(stderr,"prepare_v2 error\n"); 
			fprintf(stderr,sqlite3_errmsg(db));
		
		}
		sqlite3_finalize(stmt); 		

	}


}


int process_login(struct bufferevent *bev,int cmd,cJSON *param){
	fprintf(stdout,"process_login cmd=%d\n",cmd);

	sqlite3_stmt * stmt = NULL; 
	const char *zTail;
	int ret;
	int pc;
	char* username;
	char* passwd;
	cJSON* cj;
	cJSON* cj_user;
	cJSON* resp_param;
	int fd;

	pc = cJSON_GetArraySize(param);
	if(2 != pc){
		fprintf(stderr,"param size must be 2 now is %d\n",pc);
		return 0;
	}
	cj = cJSON_GetArrayItem(param,0);
	username = cj->valuestring;
	cj = cJSON_GetArrayItem(param,1);
	passwd = cj->valuestring;

	fprintf(stdout,"username = %s passwd = %s\n",username,passwd);

	ret = sqlite3_prepare_v2(db,select_user_by_username, -1, &stmt, &zTail);
	if(SQLITE_OK  != ret){
		fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
		return 0;
	}
	
	sqlite3_bind_text(stmt,1,username,strlen(username),NULL);
	ret = sqlite3_step(stmt);
	if(SQLITE_DONE == ret){
		sqlite3_reset(stmt);
		ret = sqlite3_prepare_v2(db,insert_user, -1, &stmt, &zTail);
		if(SQLITE_OK  != ret){
			fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
			return 0;
		}		
		sqlite3_bind_text(stmt,1,username,strlen(username),NULL);
		ret = sqlite3_step(stmt);
	}
	sqlite3_reset(stmt);
	ret = sqlite3_prepare_v2(db,select_user_by_username, -1, &stmt, &zTail);
	
	if(SQLITE_OK  != ret){
		fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
		return 0;
	}
	sqlite3_bind_text(stmt,1,username,strlen(username),NULL);

	ret = sqlite3_step(stmt);

	if(SQLITE_ROW == ret){
			resp_param = cJSON_CreateArray();
			cj_user = cJSON_CreateObject();
			
			int64_t id = sqlite3_column_int(stmt,0);
			char* username = sqlite3_column_text( stmt, 1);
			char* passwd = sqlite3_column_text( stmt, 2); 
			char* nickname = sqlite3_column_text( stmt, 3);
			char* head = sqlite3_column_text( stmt, 4); 
			int   money = sqlite3_column_int( stmt, 5);
			cJSON_AddNumberToObject(cj_user,"id",id);
			cJSON_AddStringToObject(cj_user,"username",username);
			cJSON_AddStringToObject(cj_user,"nickname",nickname);
			cJSON_AddStringToObject(cj_user,"head",head);
			cJSON_AddNumberToObject(cj_user,"money",money);
			cJSON_AddItemToArray(resp_param,cj_user);
			send_param(bev,s2c_login,resp_param,ec_success);
	
			cJSON_Delete(resp_param);


			//kick
			fd = bufferevent_getfd(bev);
			int i=0;
			for(i = 0;i<MAX_CLIENT;i++){
				if(conn_clients[i]
					&& i != fd && conn_clients[i]->usr->id == id){
					
					struct conn_client *cc = conn_clients[i];
					if(cc){
						bufferevent_free(cc->bev);
						free(cc->usr);
						free(cc);
						conn_clients[i] = NULL;
					}
					
				}
			}
			

		
			evutil_socket_t fd = bufferevent_getfd(bev);
			struct conn_client* cc = conn_clients[fd];
			cc->usr->id = id;
			snprintf(cc->usr->username,sizeof(cc->usr->username),username);
			snprintf(cc->usr->passwd,sizeof(cc->usr->passwd),passwd);
			snprintf(cc->usr->nickname,sizeof(cc->usr->nickname),nickname);
			snprintf(cc->usr->head,sizeof(cc->usr->head),head);
			snprintf(cc->usr->username,sizeof(cc->usr->username),username);
			cc->usr->money = money;

			cc->us = us_logined;


			
			
			fprintf(stdout,"id = %lld username=%s passwd=%s nickname=%s head=%s money=%d\n",id,username,passwd,nickname,head,money);		

	}else{
		fprintf(stderr,"sqlite3_setp error ret=%d\n",ret);

	}
	
	sqlite3_finalize(stmt);
	
	return 1;
}

int process_message(struct bufferevent *bev,char *msg,int len){
	fprintf(stdout,"process_message msg=%s len=%d\n",msg,len);
	int cmd = 0;
	int fd = bufferevent_getfd(bev);
	struct conn_client *conn_clt = conn_clients[fd];
	cJSON *param = NULL;
	int ret = parse_request(msg+8,&cmd,&param);
	if(!ret){
		fprintf(stderr,"can't parse len %d msg %s\n",len,msg);
		return 0;
	}
	if(c2s_login == cmd
		&& conn_clt->us == us_logined){
		fprintf(stderr,"you have logined\n");
		return 0;
	}

	switch(cmd){
		case c2s_login:
			process_login(bev,cmd,param);
			break;
		
		default:
			fprintf(stderr,"invalid cmd %d\n",cmd);
	}

	
	return 1;
}

int process_send(struct bufferevent *bev,char *buff,int len){
	int len_out = 0;
	char* buff_out = malloc(len*2);
	buildFrame(buff,len,buff_out,&len_out);
	struct evbuffer* dst = bufferevent_get_output(bev);
	evbuffer_add(dst,buff_out,len_out);
	free(buff_out);
	return 1;
}

int send_param(struct bufferevent *bev,int cmd,cJSON* param,int ec){
	cJSON* root = cJSON_CreateObject();
	cJSON* param_copy = cJSON_Duplicate(param,1);
	cJSON_AddNumberToObject(root,"cmd",cmd);
	cJSON_AddItemToObject(root,"param",param_copy);
	cJSON_AddNumberToObject(root,"ec",ec);
	char* json = cJSON_Print(root);
	int json_len = strlen(json);
	char* buff = malloc(json_len+8+1);
	strncpy(buff,"<-------",8);
	strncpy(buff+8,json,json_len);
	buff[json_len+8+1-1] = '\0';
	process_send(bev,buff,json_len+8+1);
	free(json);
	free(buff);
	cJSON_Delete(root);
	return 1;
}





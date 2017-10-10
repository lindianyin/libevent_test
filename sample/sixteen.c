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
	c2s_enter_table,
	s2c_enter_table,
	c2s_leave_table,
	s2c_leave_table,
	c2s_bet,
	s2c_bet,
	s2c_cards,
	s2c_tally_result,
	s2c_status_change,
	s2c_update_money,
	s2c_broadcast_player,
};


enum error_code{
	ec_success = 0,
	ec_full_postion = -1,
	ec_not_enouth = -2,
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
	ps_ready,
	ps_left,
};

enum player_type{
	pt_normal,
	pt_system,
};


struct player{
	struct conn_client* conn_clt;
	struct user* usr;
	enum player_status ps;
	enum player_type pt;
	int bet[4];
};

enum table_status{
	ts_betting,
	ts_turning,
	ts_balancing,
};

struct cards{
	int card[2];
};

enum player_action{
	pa_add,
	pa_delete,
	pa_update,
};



#define MAX_POSTION (256)
#define BANKER_POSTION (0)
struct table{
	struct player* play_postion[MAX_POSTION];
	enum table_status ts;
	int duration;
	struct cards cards[4];
};

enum tally_result{
	tr_ok,
	tr_not_enough,
};


//sql
const char* select_user_by_username = "select id,username,passwd,nickname,head,money from user where username = ?;";
const char* insert_user = "INSERT INTO user (id,username,passwd,nickname,head,money) VALUES (NULL,?,\"passwd\",\"nickname\",\"head\",1000);";
const char* select_money_by_id = "select money from user where id = ?;";
const char* update_user_moeny = "update user set money = ? where id = ?;";

//global
static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct evconnlistener *listener;
static char* listen_addr;


static sqlite3* db = NULL;
static lua_State *L = NULL;

#define MAX_CLIENT (1024)

static struct conn_client* conn_clients[MAX_CLIENT];

static struct table* table;

#define FRAME (60)

struct timeval tv = {0,1e6/FRAME};

static int durations[3] = {10*FRAME,15*FRAME,5*FRAME};

#define MAX_BET (1000000)

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


void main_tick(evutil_socket_t fd, short what, void * arg);

void init_table();


int process_enter_table(struct conn_client * conn_clt,int cmd,cJSON *param);
int process_leave_table(struct conn_client * conn_clt,int cmd,cJSON *param);
int process_bet(struct conn_client * conn_clt,int cmd,cJSON *param);




void betting_to_turning();

void turing_to_balancing();

void balancing_to_betting();

void shuffle_cards();

int calc_cards_score(int* cards);
int tally(int id,int money,enum tally_result *tr,int *now_money);
void status_change(enum table_status ts_from,enum table_status ts_to);


int
main(int argc, char **argv)
{
	int i;
	int socklen;
	int ret;
	int c;
	struct event * timer;
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


	//game init
	init_table();
	
	
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


	//timer tick
	timer = evtimer_new(base, main_tick, NULL);
	evtimer_add(timer, &tv);







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
	//buff_out[pos] = buff_out[pos] | 0x1;//text frame
	buff_out[pos] = buff_out[pos] | 0x2;//binary frame	
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
				fprintf(stdout,"id = %lld username=%s passwd=%s nickname=%s head=%s money=%d\n",(long long)id,username,passwd,nickname,head,money);
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


			
			
			fprintf(stdout,"id = %lld username=%s passwd=%s nickname=%s head=%s money=%d\n",(long long)id,username,passwd,nickname,head,money);		

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
		cJSON_Delete(param);
		return 0;
	}
	if(c2s_login == cmd
		&& conn_clt->us == us_logined){
		fprintf(stderr,"you have logined\n");
		cJSON_Delete(param);
		return 0;
	}
	if(c2s_login != cmd
		&& conn_clt->us != us_logined){
		fprintf(stderr,"you must login firstly\n");
		cJSON_Delete(param);
		return 0;
	}


	

	switch(cmd){
		case c2s_login:
			process_login(bev,cmd,param);
			break;
		case c2s_enter_table:
			process_enter_table(conn_clt,cmd,param);
			break;
		case c2s_leave_table:
			process_leave_table(conn_clt,cmd,param);
			break;
		case c2s_bet:
			process_bet(conn_clt,cmd,param);
			break;
		default:
			fprintf(stderr,"invalid cmd %d\n",cmd);
	}
	cJSON_Delete(param);
	
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
	char* json = cJSON_PrintUnformatted(root);
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

void update_money(struct conn_client* conn_clt,int money){
	cJSON* resp_param = cJSON_CreateArray();
	cJSON* ret = NULL;
	cJSON_AddItemToArray(resp_param,ret = cJSON_CreateNumber(money));
	conn_clt->usr->money = money;
	send_param(conn_clt->bev,s2c_update_money,resp_param,ec_success);
}


void main_tick(evutil_socket_t fd, short what, void * arg){
	//timer tick
	struct event* timer = evtimer_new(base, main_tick, NULL);
	evtimer_add(timer, &tv);

	table->duration--;

	if(table->ts == ts_betting
		&& table->duration == 0){
		fprintf(stdout,"from betting to turning\n");
		table->ts = ts_turning;
		table->duration = durations[table->ts];
		betting_to_turning();
		status_change(ts_betting,ts_turning);
	}else if(table->ts == ts_turning
		&& table->duration == 0){
		fprintf(stdout,"from turning to balancing\n");
		table->ts = ts_balancing;
		table->duration = durations[table->ts];
		turing_to_balancing();
		status_change(ts_turning,ts_balancing);
	}else if(table->ts == ts_balancing
		&& table->duration == 0){
		fprintf(stdout,"from balancing to betting\n");
		table->ts = ts_betting;
		table->duration = durations[table->ts];
		balancing_to_betting();
		status_change(ts_balancing,ts_betting);
	}
	
	
}

void init_table(){
	table = calloc(sizeof(*table),1);
	table->ts = ts_betting;
	table->duration = durations[table->ts];
	shuffle_cards();
}

int process_enter_table(struct conn_client * conn_clt,int cmd,cJSON *param){
	int i;
	int flag = 0;
	struct player* player = NULL;
	for(i = BANKER_POSTION+1;i<MAX_POSTION;i++){
		struct player* p = table->play_postion[i];
		if(p && p->usr->id == conn_clt->usr->id){
			player = p;
			flag = 1;
			break;
		}
	}
	if(!flag){
		for(i = BANKER_POSTION+1;i<MAX_POSTION;i++){
			if(!table->play_postion[i]){
				struct player* p = calloc(sizeof(*p),1);
				struct user* usr = calloc(sizeof(*usr),1);
				memcpy(usr,conn_clt->usr,sizeof(*usr));//we must copy memory ,so we don't need to rely on the life cycle of  the conn_client.
				p->usr = usr;
				p->ps = ps_ready;
				p->pt = pt_normal;
				p->conn_clt = conn_clt;
				table->play_postion[i] = p;
				player = p;
				break;
			}
		}
	}

	int ec = ec_success;
	if(i >= MAX_POSTION){
		ec = ec_full_postion;
	}

	
	broadcast_player(player,pa_add);
	
	cJSON * resp_param = cJSON_CreateArray();
	cJSON * ret = NULL;
	cJSON_AddItemToArray(resp_param,cJSON_CreateNumber(i));
	cJSON_AddItemToArray(resp_param,cJSON_CreateNumber(table->ts));
	send_param(conn_clt->bev,s2c_enter_table,resp_param,ec);
	cJSON_Delete(resp_param);
	return 1;
}



int process_leave_table(struct conn_client * conn_clt,int cmd,cJSON *param){
	int i;
	int flag = 0;
	struct player* player = NULL;
	for(i = BANKER_POSTION+1;i<MAX_POSTION;i++){
		struct player* p = table->play_postion[i];
		if(p && p->usr->id == conn_clt->usr->id){
			flag = 1;
			player = p;
			break;
		}
	}
	if(!flag){
		fprintf(stderr,"can't find the player on the table\n");
		return 0;
	}
	player->ps = ps_left;
	player->conn_clt = NULL;

	broadcast_player(player,pa_delete);

	
	cJSON * resp_param = cJSON_CreateArray();
	cJSON * ret = NULL;
	cJSON_AddItemToArray(resp_param,ret = cJSON_CreateNumber(i));

	send_param(conn_clt->bev,s2c_leave_table,resp_param,ec_success);
	cJSON_Delete(resp_param);
	return 1;
}


int process_bet(struct conn_client * conn_clt,int cmd,cJSON *param){

	if(table->ts != ts_betting){
		fprintf(stderr,"can't bet because of now is %d status\n",table->ts);
		return 0;
	}
	
	int len = cJSON_GetArraySize(param);
	if(2 != len){
		fprintf(stderr,"len must be 1 now is %d\n",len);
		return 0;
	}

	cJSON* cjpos = cJSON_GetArrayItem(param,0);
	if(!cJSON_IsNumber(cjpos)){
		fprintf(stderr,"the item must be a number \n");
		return 0;
	}
	int pos = cjpos->valueint;

	if(pos > 3 || pos < 1){
		fprintf(stderr,"the pos must be from 1 to 3 now is %d\n",pos);
		return 0;
	}

	cJSON* cjbet = cJSON_GetArrayItem(param,1);
	if(!cJSON_IsNumber(cjbet)){
		fprintf(stderr,"the item must be a number \n");
		return 0;
	}
	int bet = cjbet->valueint;

	if(bet <= 0 || bet > MAX_BET){
		fprintf(stderr,"invalid bet is  %d\n",bet);
		return 0;
	}

	int i;
	int flag = 0;
	struct player* player = NULL;
	for(i = BANKER_POSTION+1;i<MAX_POSTION;i++){
		struct player* p = table->play_postion[i];
		if(p && p->usr->id == conn_clt->usr->id){
			flag = 1;
			player = p;
			break;
		}
	}	
	if(!flag){
		fprintf(stderr,"player do't enter table\n");
		return 0;
	}
	enum tally_result tr = tr_ok;
	int now_moeny = 0;
	int tret;
	tret = tally(player->usr->id,-1 * bet,&tr,&now_moeny);
	int ec = ec_success;
	if(!tret){
		fprintf(stderr,"tally failed\n");
		if(tr == tr_not_enough){
			ec = ec_not_enouth;
		}
	}else{
		fprintf(stdout,"befor bet is %d\n",player->bet[pos]);
		player->bet[pos] += bet;
		fprintf(stdout,"after bet is %d\n",player->bet[pos]);

		update_money(conn_clt,now_moeny);
		player->usr->money = now_moeny;
	}

	//notify to others
	
	cJSON * resp_param = cJSON_CreateArray();
	send_param(conn_clt->bev,s2c_bet,resp_param,ec);
	cJSON_Delete(resp_param);
	return 1;
}






void betting_to_turning(){
	//send all card to all player on the table

	cJSON *resp_param = cJSON_CreateArray();
	int i;
	cJSON *ret = NULL;
	for(i = 0;i < 4;i++){
		cJSON_AddItemToArray(resp_param,cJSON_CreateIntArray(table->cards[i].card,2));
	}
	for(i = 0;i<MAX_POSTION;i++){
		if(table->play_postion[i]
			&& table->play_postion[i]->ps != ps_left){
			if(table->play_postion[i]->conn_clt){
				struct bufferevent* bev = table->play_postion[i]->conn_clt->bev;
				send_param(bev,s2c_cards,resp_param,ec_success);
			}
			
		}
	}
	char* json = cJSON_Print(resp_param);
	fprintf(stdout,"json=%s\n",json);
	free(json);
	cJSON_Delete(resp_param);
} 


void turing_to_balancing(){
	//calculate the result by compare with the banker
	int result_score[4];
	int i;
	for(i = 0;i<4;i++){
		result_score[i] = calc_cards_score(table->cards[i].card);
	}

	//for banker 1 for win 0 for draw and -1 for lost
	int result[4];
	for(i = 1 ;i< 4;i++){
		if(result_score[0] > result_score[i+1]){
			result[i] = 1;
		}else if(result_score[0] == result_score[i+1]){
			result[i] = 0;
		}else{
			result[i] = -1;
		}
	}

	for(i = 0;i<MAX_POSTION;i++){
		
		struct player* p = table->play_postion[i];
		if(p){
			int j;
			int result_bet[4];
			result_bet[0] = 0;
			int sum = 0;//for banker
			for(j = 1;j<4;j++){
				if(result[j] == 1){
					result_bet[j] = 0;
 				}else if(result[j] == 0){
					result_bet[j] = -1 * p->bet[j];
				}else{
					result_bet[j] = -1 * p->bet[j];
				}
				sum += result_bet[j];
				enum tally_result tr;
				int now_money;
				int tret;
				tret = tally(p->usr->id,-1*sum,&tr,&now_money);
				fprintf(stdout,"sum = %d tr=%d,now_money=%d tret = %d\n",sum,tr,now_money,tret);
				update_money(p->conn_clt,now_money);
				p->usr->money = now_money;
			}

			cJSON* resp_param = cJSON_CreateArray();
			cJSON* ret = NULL;
			cJSON_AddItemToArray(resp_param,ret = cJSON_CreateIntArray(result_bet,4));
			if(p->ps != ps_left){
				send_param(p->conn_clt->bev,s2c_tally_result,resp_param,ec_success);
			}
			cJSON_Delete(resp_param);
		}

	}

}

void balancing_to_betting(){
	//clear all status

	//clear before bet
	int i;
	for(i = 0;i < MAX_POSTION; i++){
		struct player *p = table->play_postion[i];
		if(NULL == p){
			continue;
		}
		memset(p->bet,0,sizeof(p->bet));
	}

	//deal card
	shuffle_cards();

	enum tally_result tr = tr_ok;
	int now = 0;
	int ret = tally(1,-560,&tr,&now);
	fprintf(stdout,"ret=%d tr=%d now=%d\n",ret,tr,now);
}


void shuffle_cards(){
	int _cards[36];
	int i;
	int num = 1;
	for(i = 0;i<36;i+=4){
		_cards[i]   = num;
		_cards[i+1] = num;
		_cards[i+2] = num;
		_cards[i+3] = num;
		num++;
	}
	for(i = 0;i<36;i++){
		int r = rand() % 36;
		int tmp = _cards[i];
		_cards[i] = _cards[r];
		_cards[r] = tmp;
	}
	int idx = 0;
	for(i = 0;i<4;i++){
		table->cards[i].card[0] = _cards[idx++];
		table->cards[i].card[1] = _cards[idx++];
		if(table->cards[i].card[0] > table->cards[i].card[1]){
			int tmp = table->cards[i].card[0];
			table->cards[i].card[0] = table->cards[i].card[1];
			table->cards[i].card[1] = tmp;
		}

		fprintf(stdout,"deal card i = %d %d %d %d\n",i,table->cards[i].card[0],table->cards[i].card[1],calc_cards_score(table->cards[i].card));
	}
}

//cards size must be 2 and sorted by asc
int calc_cards_score(int* cards){
	int score = 0;
	if(cards[0] == cards[1]){
		score += 10;
		score += cards[0];
	}else{
		if(cards[0] == 2 && cards[1] == 8){
			score = 10;
		}else{
			score = (cards[0] + cards[1]) % 10;
		}
	}
	return score;
}

//when tally return 1 ,and then the other out param is valid
//when tally return 0 ,and tr is tr_not_enough,indicate that the user don't have enough money
//TODO:this function must be add transaction.
int tally(int id,int money,enum tally_result *tr,int *now_money){
	sqlite3_stmt * stmt = NULL; 
	const char *zTail;	
	int ret;
	ret = sqlite3_prepare_v2(db,select_money_by_id, -1, &stmt, &zTail);
	if(SQLITE_OK  != ret){
		fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
		sqlite3_finalize(stmt);
		return 0;
	}
	sqlite3_bind_int(stmt,1,id);
	ret = sqlite3_step(stmt);
	int m = 0;
	if(SQLITE_ROW == ret){
		m = sqlite3_column_int(stmt,0);
	}
	fprintf(stdout,"id = %d m = %d\n",id,m);
	
	int rm = 0;
	if(money < 0){
		if(m > abs(money)){
			//update
			rm = m - abs(money);
		}else{
			//not enough money
			*tr = tr_not_enough;
			sqlite3_finalize(stmt);
			return 0;
		}
	}else{
		rm = m + abs(money);

	}
	sqlite3_reset(stmt);
	ret = sqlite3_prepare_v2(db,update_user_moeny, -1, &stmt, &zTail);
	if(SQLITE_OK  != ret){
		fprintf(stderr,"prepare_v2 error ret=%d\n",ret);
		sqlite3_finalize(stmt);
		return 0;
	}
	sqlite3_bind_int(stmt,1,rm);
	sqlite3_bind_int(stmt,2,id);
	ret = sqlite3_step(stmt);

	*now_money = rm;
	*tr = tr_ok;
	
	sqlite3_finalize(stmt);
	return 1;
}

void status_change(enum table_status ts_from,enum table_status ts_to){
	cJSON* resp_param = cJSON_CreateArray();
	cJSON* ret = NULL;
	int ss[2] = {ts_from,ts_to};
	cJSON_AddItemToArray(resp_param,ret = cJSON_CreateIntArray(ss,2));
	int i;
	for(i = 0;i<MAX_POSTION;i++){
		struct player* p = table->play_postion[i];
		if(p && p->ps != ps_left){
			send_param(p->conn_clt->bev,s2c_status_change,resp_param,ec_success);
		}
	}
	cJSON_Delete(resp_param);
}

void broadcast_player(struct player *player,enum player_action pa){
	cJSON* resp_param = cJSON_CreateArray();
	cJSON* ret = NULL;
	cJSON_AddItemToArray(resp_param,ret = cJSON_CreateObject());
	cJSON_AddStringToObject(ret,"id",player->usr->id);
	cJSON_AddStringToObject(ret,"head",player->usr->head);
	cJSON_AddStringToObject(ret,"nickname",player->usr->nickname);
	cJSON_AddNumberToObject(ret,"money",player->usr->money);
	
	cJSON_AddItemToArray(resp_param,cJSON_CreateNumber(pa));


	int i;
	for(i = 0;i<MAX_POSTION;i++){
		struct player* p = table->play_postion[i];
		if(p && p->ps != ps_left){
			send_param(p->conn_clt->bev,s2c_broadcast_player,resp_param,ec_success);

		}
	}
	cJSON_Delete(resp_param);
}


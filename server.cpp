#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <list>           
#include <queue>
#include <thread>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "common.h"
#include <arpa/inet.h>
#include<pthread.h>

using namespace std;
pthread_mutex_t mutex;
pthread_mutex_t list_mutex;
void error(const char *msg){
    perror(msg);
    exit(1);
}



struct Packet{
	char source[USERNAME_SIZE];
	char dest[USERNAME_SIZE];
	unsigned char* msg;
	unsigned int msgsize;
	short cmdcode;
};

struct User{
	char nickname[USERNAME_SIZE];
	char peer_nickname[USERNAME_SIZE];
	queue<Packet> inputqueue;
	queue<Packet> outputqueue;
	unsigned int send_counter=0;
	unsigned int recv_counter=0;
	bool online=false;
	bool done=false;
	bool paired=false;
};

struct Args{
	int socket;
	User* arguser;
	unsigned char* sessionkey=NULL;
	
};

list<User> users;



void send_userlist(int socket,  User* current_user, unsigned char* sessionkey){
	int ret;
	unsigned int msg_size=0;
	unsigned char* message = (unsigned char*)malloc(MAX_CLIENTS*USERNAME_SIZE);
	if(!message){cerr<<"send userlist: message Malloc Error";exit(1);}
	for(list<User>::iterator it=users.begin(); it != users.end();it++){
		if(strcmp(it->nickname,current_user->nickname) != 0 && it->online){
			memcpy(message+msg_size,it->nickname,strlen(it->nickname)+1);
			msg_size+=strlen(it->nickname)+1;
		}
	}
	
	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));
	if(!aad){cerr<<"send userlist: aad Malloc Error";exit(1);}
	memcpy(aad,(unsigned char*)&current_user->send_counter,sizeof(unsigned int));
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"send userlist: buffer Malloc Error";exit(1);}
	ret=encryptor(1,aad, sizeof(unsigned int), message, msg_size , sessionkey, buffer);
	if (ret>=0){
		send_msg(socket,ret,buffer);
		increment_counter(current_user->send_counter);
	}
	free(buffer);
	free(message);
	free(aad);
}


//thread function to manage the output queue
void *outputqueue_handler(void* arguments){
	Args *args = (Args*) arguments;
	int socket= args->socket;
	User* current_user= args->arguser;
	unsigned char* sessionkey=args->sessionkey;
	int ret;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"outputqueue handler: buffer Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"outputqueue handler: aad Malloc Error";exit(1);}
	pthread_mutex_lock(&mutex);
	bool done=current_user->done;
	pthread_mutex_unlock(&mutex);
	while(!done){
		pthread_mutex_lock(&mutex);
		if(!(current_user->outputqueue.empty())){
			Packet message = current_user->outputqueue.front();
			
			if(message.msgsize<=MSG_MAX){			
				current_user->outputqueue.pop();
				memcpy(aad,(unsigned char*)&current_user->send_counter,sizeof(unsigned int));
				memcpy(aad+sizeof(unsigned int),message.msg,message.msgsize);
				ret=encryptor(message.cmdcode, aad, message.msgsize+sizeof(unsigned int), (unsigned char*)message.source,strlen(message.source)+1,sessionkey,buffer);
				if (ret>=0){
					send_msg(socket,ret,buffer);
					increment_counter(current_user->send_counter);
				}
				if(message.cmdcode == 8){
					current_user->online=true;
					current_user->paired=false;
				}
				else if(message.cmdcode == 4){
					current_user->online=true;
				}
				else if (message.cmdcode == 2){
					current_user->online=false;
				}
			}
		}
		done=current_user->done;
		pthread_mutex_unlock(&mutex);
	}
	free(buffer);
	free(aad);
	cout<<current_user->nickname<<": queue thread done."<<endl;	
	pthread_exit(NULL);
	return NULL;
}


//thread function
void *client_handler(void* arguments) {
	Args *args = (Args*) arguments;
	int socket= args->socket;
	User* current_user= args->arguser;
	int ret;
	uint32_t networknumber;
	unsigned int clientnumber;
	unsigned int received=0;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"establishSession: buffer Malloc Error";exit(1);}
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<"establishSession: message Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"establishSession: message Malloc Error";exit(1);}


// SESSION ESTABLISHMENT

	//retrieve server key
	EVP_PKEY* server_key;
	
	FILE* file = fopen("serverFiles/s_key.pem", "r");
	if(!file) {cerr<<"establishSession: s_k File Open Error\n";exit(1);}   
	server_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!server_key) {cerr<<"establishSession: server_key Error\n";exit(1);}
	fclose(file);
	//receive signature

	int msg_size=receive_msg(socket, buffer);
	if(msg_size==0) {cerr<<"establishSession: receive signed message error";exit(1);}

	unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size+=sizeof(unsigned int);
	unsigned int username_size = msg_size-sgnt_size- NONCE_SIZE;
	if(username_size<=0){ cerr << "establishSession: no nickname \n"; exit(1); }
	if(username_size>=USERNAME_SIZE){ cerr << "establishSession: nickname too long \n"; exit(1); }
	char nickname[username_size+1];	
	memcpy(nickname, buffer+sgnt_size+NONCE_SIZE, username_size);
	nickname[username_size]='\0';
	pthread_mutex_lock(&mutex);
	strncpy(current_user->nickname, nickname, username_size+1);
	pthread_mutex_unlock(&mutex);
	string filename = "serverFiles/"+(std::string)nickname+"_pub.pem";
	cerr<<"client pub key filename: "<<filename<<endl;
	//Get user pubkey
	EVP_PKEY* client_pubkey;
	FILE* file3 = fopen( filename.c_str(), "r");
	if(!file3) {
	cerr<<"establishSession: Incorrect Username";
	return NULL;}   
	client_pubkey= PEM_read_PUBKEY(file3, NULL, NULL, NULL);
	if(!client_pubkey) {cerr<<"establishSession: Pubkey Error";exit(1);}
	fclose(file3);
	 
	// verify signature and store received nonce
	//ret=digsign_verify(client_pubkey,buffer, msg_size,signature_buffer,signature_size);
	ret=digsign_verify(client_pubkey,buffer, msg_size, message);
	if(ret<0){cerr<<"establishSession: invalid signature!"; return NULL ;}
	unsigned char* receivednonce=(unsigned char*)malloc(NONCE_SIZE);
	memcpy(receivednonce, message, NONCE_SIZE);
	
	//Send certificate and ecdhpubkey.
	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"establishSession: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"establishSession: RAND_bytes Error";exit(1);}
	
	
	uint32_t size;
	X509* serverCert;
	FILE* certfile = fopen("serverFiles/s_cert.pem", "r");
	if(!certfile) { cerr<<"establishSession:cert File Open Error\n";exit(1);}
	serverCert = PEM_read_X509(certfile, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"establishSession: PEM_read_X509 error\n";exit(1); }
	fclose(certfile);
	 BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"establishSession: Failed to allocate BIO_s_mem\n";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"establishSession: PEM_write_bio_X509 error\n";exit(1); }
	unsigned char* certbuffer=NULL;
	long certsize= BIO_get_mem_data(bio, &certbuffer);
	size=htonl(certsize);
	ret=send(socket, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"establishSession: Error writing to socket";exit(1);}
	ret=send(socket, certbuffer, certsize, 0);
	if(ret<=0){cerr<<"establishSession: Error writing to socket";exit(1);}
	
//Generate ECDH key pair
	EVP_PKEY* dhpvtkey=dh_generate_key();
	unsigned char* buffered_ECDHpubkey=NULL;
	BIO* kbio = BIO_new(BIO_s_mem());
	if(!kbio) { cerr<<"establishSession: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(kbio,   dhpvtkey)) { cerr<<"establishSession: PEM_write_bio_PUBKEY error";exit(1); }
	long pubkeysize = BIO_get_mem_data(kbio, &buffered_ECDHpubkey);
	if (pubkeysize<=0) { cerr<<"establishSession: BIO_get_mem_data error";exit(1); }
	msg_size= pubkeysize+NONCE_SIZE+NONCE_SIZE;
//Sign Message
	memcpy(message,receivednonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE,mynonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE+NONCE_SIZE,buffered_ECDHpubkey,pubkeysize);
	unsigned int signed_size=digsign_sign(server_key, message, msg_size,buffer);
	free(receivednonce);
	send_msg(socket, signed_size, buffer);
	BIO_free(bio);
	BIO_free(kbio);
	EVP_PKEY_free(server_key);
	//Get ecdhpubkey from client
	signed_size=receive_msg(socket, buffer);
	unsigned int signature_size=*(unsigned int*)buffer;
	signature_size+=sizeof(unsigned int);
	if(memcmp(buffer+signature_size,mynonce,NONCE_SIZE)!=0){
				cerr<<"establishSession: nonce received is not valid!\n";
				return NULL;}
	msg_size= digsign_verify(client_pubkey,buffer,signed_size,message);
	if(msg_size<=0){cerr<<"establishSession: signed message error!\n"; return NULL;}
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, message+NONCE_SIZE, msg_size-NONCE_SIZE);
	EVP_PKEY* ecdh_client_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	
	size_t slen;
	EVP_PKEY_CTX *derive_ctx;
	derive_ctx = EVP_PKEY_CTX_new(dhpvtkey, NULL);
	if (!derive_ctx) handleErrors();
	if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
	/*Setting the peer with its pubkey*/
	if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_client_pubkey) <= 0) handleErrors();
	/* Determine buffer length, by performing a derivation but writing the result nowhere */
	EVP_PKEY_derive(derive_ctx, NULL, &slen);
	unsigned char* shared_secret = (unsigned char*)(malloc(int(slen)));	
	if (!shared_secret) {cerr<<"establishSession: sharedsecret MALLOC ERR";exit(1);}
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0) {cerr<<"ERR";exit(1);}
	EVP_PKEY_CTX_free(derive_ctx);
	BIO_free(mbio);
	EVP_PKEY_free(ecdh_client_pubkey);
	EVP_PKEY_free(dhpvtkey);
	unsigned char* sessionkey=(unsigned char*) malloc(EVP_MD_size(md));
	if (!sessionkey) {cerr<<"establishSession: sessionkey MALLOC ERR";exit(1);}
	ret=dh_generate_session_key(shared_secret, (unsigned int)slen, sessionkey);
	free(shared_secret);	
	args->sessionkey=sessionkey;
	short cmdcode;
	unsigned int aadlen;
	unsigned int msglen;
	current_user->online=true;
	send_userlist(socket,current_user,sessionkey);
	pthread_t outputmanager;
	if( pthread_create(&outputmanager, NULL, &outputqueue_handler, (void *)args)  != 0 )
		printf("Failed to create thread\n");
	pthread_mutex_lock(&mutex);	
	bool done= current_user->done;
	pthread_mutex_unlock(&mutex);
	while(!done){	
		msg_size=receive_msg(socket,buffer);
		pthread_mutex_lock(&mutex);
		if(msg_size>0&&!current_user->done){
			unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
			
			if(received_counter==current_user->recv_counter){
				ret=decryptor(buffer, msg_size, sessionkey,cmdcode, aad, aadlen, message);
				increment_counter(current_user->recv_counter);
				
						
				switch(cmdcode){
					case 0://quit
					{					
						current_user->online=false;
						cout<<current_user->nickname<<" has exited."<<endl;
						current_user->done=true;						
					}break;
					case 1:
					{
						send_userlist(socket,current_user,sessionkey);
					}break;
					case 2://rtt
					{	
						if(current_user->online&&ret>0&&ret<=USERNAME_SIZE){
							Packet rtt;		
							bool found=false;
							strncpy(rtt.source,current_user->nickname,USERNAME_SIZE);
							memcpy(rtt.dest,message,ret);
							rtt.dest[ret]='\0';
							rtt.msg=(unsigned char*) malloc(NONCE_SIZE);
							if(!rtt.msg){cerr<<"msg malloc error"; exit(1);}
							memcpy(rtt.msg,aad+sizeof(unsigned int),NONCE_SIZE);
							rtt.msgsize=NONCE_SIZE;
							for(list<User>::iterator it =users.begin(); it != users.end();it++){
								if(strncmp(it->nickname,rtt.dest,strlen(rtt.dest))==0 && it->online){
									found=true;
									current_user->online=false;
									rtt.cmdcode=cmdcode;
									cout<<"forwarded rtt"<<endl;
								}										
							}
							if(!found||strcmp(rtt.source,rtt.dest)==0){
								strncpy(rtt.dest ,current_user->nickname,USERNAME_SIZE);
								rtt.cmdcode = 7;	
								current_user->online=true;
								cout<<"forwarded refuse , user not found"<<endl;								
							}
							current_user->inputqueue.push(rtt);
						}
					}break;
					case 3:
					{	
					cout<<"received accept "<<endl;
						if(!current_user->paired){
							Packet key;
							char peerusername[USERNAME_SIZE];	
 						
							strncpy(key.source,current_user->nickname,USERNAME_SIZE);
							memcpy(key.dest,message,USERNAME_SIZE);
							memcpy(peerusername,message,USERNAME_SIZE);	
							memcpy(current_user->peer_nickname,message,USERNAME_SIZE);			
							BIO* mybio = BIO_new(BIO_s_mem());
							PEM_write_bio_PUBKEY(mybio,client_pubkey);
							char* mypubkey_buf=NULL;
							long pubkey_size =BIO_get_mem_data(mybio,&mypubkey_buf);
							key.msg=(unsigned char*) malloc(((int)pubkey_size)+sizeof(long)+aadlen-sizeof(unsigned int));
							if(!key.msg){cerr<<"msg malloc error"; exit(1);}
							key.msgsize=pubkey_size+aadlen+sizeof(long)-sizeof(unsigned int);
							cout<<key.msgsize<<", signed part: "<<aadlen-sizeof(unsigned int)<<", key: "<<pubkey_size<<endl;   
							memcpy(key.msg,(unsigned char*) &pubkey_size,sizeof(long));
							memcpy(key.msg+sizeof(long),mypubkey_buf,pubkey_size);
							// copy ecdhpubkey signature from current_user to the peer
							memcpy(key.msg+pubkey_size+sizeof(long),aad+sizeof(unsigned int),aadlen-sizeof(unsigned int));
							BIO_free(mybio);					 
							key.cmdcode=cmdcode;		
							string fname = "serverFiles/"+(string)peerusername+"_pub.pem";
							//Get peer pubkey						
							FILE* file2 = fopen( fname.c_str(), "r");
							if(!file2) {
								cerr<<"Accept: Incorrect peer Username\n";
								
							}   
							else{ 
								EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(file2, NULL, NULL, NULL);
								if(!peer_pubkey) {cerr<<"Accept: Pubkey Error";exit(1);}
								BIO* thatbio = BIO_new(BIO_s_mem());
								PEM_write_bio_PUBKEY(thatbio,peer_pubkey);
								char* thatpubkey_buf=NULL;
								pubkey_size =BIO_get_mem_data(thatbio,&thatpubkey_buf);
								unsigned int newaadlen=(unsigned int)pubkey_size+sizeof(unsigned int);
								unsigned char* newaad=(unsigned char*) malloc(newaadlen);
								if(!newaad){cerr<<"msg malloc error"; exit(1);}
								memcpy(newaad,(unsigned char*) &current_user->send_counter,sizeof(unsigned int));
								memcpy(newaad+sizeof(unsigned int),thatpubkey_buf,(int)pubkey_size);
								BIO_free(thatbio);
								free(peer_pubkey);
								msg_size=encryptor(6,newaad, newaadlen, message, ret , sessionkey, buffer); //send peer_pubkey 
								free(newaad);
								if (msg_size>=0)
									{	
										// send to peer the user pubkey and ecdhpubkey
										current_user->inputqueue.push(key);
										// send back to current_user the peerpubk key
										send_msg(socket,msg_size,buffer);
										cout<<"sent pubkey of: "<<peerusername<<endl;
										increment_counter(current_user->send_counter);
										current_user->paired=true;
										current_user->online=false;
									}
							}fclose(file2);
						}
						
					}break;
					case 4:
					{	
						cout<<"received refuse "<<endl;
						if(!current_user->paired){
							Packet refusal;					
							strncpy(refusal.source,current_user->nickname,USERNAME_SIZE);
							memcpy(refusal.dest,message,USERNAME_SIZE);
							refusal.msgsize=0;
							refusal.cmdcode=cmdcode;
							current_user->online=true;
							current_user->inputqueue.push(refusal);
							cout<<"forwarded refuse "<<endl;
						}
					}break;
					case 5:
					{	
						if(current_user->paired){
							Packet mex;					
							strncpy(mex.source,current_user->nickname,USERNAME_SIZE);
							memcpy(mex.dest,message,USERNAME_SIZE);
							mex.msgsize=aadlen-sizeof(unsigned int);
							mex.msg=(unsigned char*) malloc(mex.msgsize);
							if(!mex.msg){cerr<<"msg malloc error"; exit(1);}
							memcpy(mex.msg,aad+sizeof(unsigned int),mex.msgsize);
							mex.cmdcode=cmdcode;
							current_user->inputqueue.push(mex);
						}
					}break;
					case 6:
					{
								
								current_user->paired=true;								
								Packet mex;					
								strncpy(mex.source,current_user->nickname,USERNAME_SIZE);
								memcpy(current_user->peer_nickname,message,USERNAME_SIZE);
								memcpy(mex.dest,message,USERNAME_SIZE);
								mex.msgsize=aadlen-sizeof(unsigned int);
								mex.msg=(unsigned char*) malloc(mex.msgsize);
								if(!mex.msg){cerr<<"msg malloc error"; exit(1);}
								memcpy(mex.msg,aad+sizeof(unsigned int), mex.msgsize);
								mex.cmdcode=6;
								current_user->inputqueue.push(mex);								
		
					}break;
					case 8:
					{
						if(current_user->paired){
							Packet end;					
							strncpy(end.source,current_user->nickname,USERNAME_SIZE);
							strncpy(end.dest,current_user->peer_nickname,USERNAME_SIZE);
							end.msgsize=0;
							end.cmdcode=cmdcode;
							current_user->inputqueue.push(end);
							msg_size=encryptor(8,(unsigned char*)&current_user->send_counter, sizeof(unsigned int), (unsigned char*)current_user->nickname, strlen(current_user->nickname) , sessionkey, buffer);
							if (msg_size>=0)
								{	
									send_msg(socket,msg_size,buffer);
									increment_counter(current_user->send_counter);
								}
							current_user->paired=false;
							current_user->online=true;
						}
					}break;
				}
			}
		}
		done=current_user->done;
		pthread_mutex_unlock(&mutex);
	}
	pthread_join(outputmanager,NULL);
	EVP_PKEY_free(client_pubkey);
	free(buffer);
	free(aad);
	free(message);
	close(socket);
	cout<<current_user->nickname<<": thread done."<<endl;	
	pthread_exit(NULL);
	return NULL;
}


int main(int argc, char *argv[]){

	unsigned int counter=0;
	int socksocket, portno;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;
	list<pthread_t> threadlist;
	if (argc < 2) {
		fprintf(stderr,"ERROR, no port provided\n");
		exit(1);
	}
	socksocket =  socket(AF_INET, SOCK_STREAM, 0);
	fcntl(socksocket, F_SETFL, O_NONBLOCK);
	if (socksocket < 0) error("ERROR opening socket");
     	bzero((char *) &serv_addr, sizeof(serv_addr));
    	portno = atoi(argv[1]);
     	serv_addr.sin_family = AF_INET;  
	serv_addr.sin_addr.s_addr = INADDR_ANY;  
	serv_addr.sin_port = htons(portno);
	if (bind(socksocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
	

	clilen = sizeof(cli_addr);
	//Listen on the socket, with 40 max connection requests queued 
  if(listen(socksocket,MAX_CLIENTS)==0)
    printf("Listening\n");
  else
    printf("Error\n");

    while(1)
    {
        //Accept call creates a new socket and thread for the incoming connection
	if(users.size()<MAX_CLIENTS){
		int newsocksocket = accept(socksocket, (struct sockaddr *) &cli_addr, &clilen);
		if (newsocksocket < 0){ 
			if (errno != EAGAIN || errno != EWOULDBLOCK)	error("ERROR on accept");
		}
		else{	
			pthread_mutex_lock(&list_mutex);
			User u;
			users.push_back(u);
			Args *args=(Args *)malloc(sizeof(struct Args));

			args->socket=newsocksocket;
			args->arguser=&users.back();
			pthread_t thread;
			threadlist.push_back(thread);
			if(pthread_create(&threadlist.back(), NULL, &client_handler, (void *)args)  != 0 )
			printf("Failed to create thread\n");
			pthread_mutex_unlock(&list_mutex);
		}
	}

	int i=0;
	pthread_mutex_lock(&list_mutex);	
	for(list<User>::iterator it=users.begin(); it != users.end();it++){
		//Check for messages in input queues and move them to dest outputqueue.
		pthread_mutex_lock(&mutex);				
		while(!(it->inputqueue.empty())){	
			Packet message = it->inputqueue.front();
			it->inputqueue.pop();
			
			for(list<User>::iterator it2=users.begin(); it2 != users.end();it2++){
				if(strcmp(message.dest, it2->nickname) == 0){
					cout<<message.source<<"-->"<<message.dest<<" "<<message.cmdcode<<endl;
					it2->outputqueue.push(message);
				}
			}
		}
		bool itdone=it->done;
		pthread_mutex_unlock(&mutex);	
		if(itdone){
			list<pthread_t>::iterator t=threadlist.begin();
			advance(t,i);
			pthread_join(*t,NULL);
			cout<<it->nickname<<": deleting."<<endl;
			it=users.erase(it);
			i++;
			if(it==users.end())
			{
				it=users.begin();
				i=0;
			}
			
		}
		i++;
	}
	pthread_mutex_unlock(&list_mutex);
	
    }	
	return 0; 
}

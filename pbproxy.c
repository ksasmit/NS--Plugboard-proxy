#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

void doprocessing (int sock,char *server_ip, char *d_port, char *keyfile);
int modec(char *server_ip, char *portno, char *keyfile);
int modes( char *port,char *server_ip, char *d_port, char *keyfile);
void fencrypt(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv);
void fdecrypt(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv);
int setNonblocking(int fd);
void *w1fun( void *ptr );
void *w2fun( void *ptr );
void *r1fun( void *ptr );
void *r2fun( void *ptr );
struct two{
	int sockfd;
	int sock;
	char* keyfile;
};
struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

AES_KEY key; 
struct ctr_state state;	 
int main(int argc, char *argv[]) {
	char *keyfile = NULL;
	char *port = NULL;
	char *dest = NULL;
	char *d_port = NULL;
	int rev_mode=0;
	int has_key = 0;
	char c;
	int index;
	while ((c = getopt (argc, argv, "k:l:")) != -1)
	{
		switch (c)
		{
			case 'l':
				rev_mode =1;//server
				port = optarg;
				break;
			case 'k':
				keyfile = optarg;
				has_key =1;
				break;
			case 'h':
				//help(1);
				return 0;
				break;
			case '?':
				if (optopt == 'k')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'l')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				//help(-1);
				return(0);
				break;
		}
	}
	int count =0;
	for (index = optind; index < argc; index++)
	{
		//printf ("Non-option argument %s\n", argv[index]);
		count++;
	}
	if(count>0)
	{
		dest = argv[optind];
	}
	if(count == 2)
	{
		d_port = argv[optind+1];
	}
	if(0 == has_key)
	{
		char* str = "1234567812345678";
		if(rev_mode) //server
			modes(port,dest,d_port,str);
		else	//client
			modec(dest,d_port,str);
	}
	else if(1 == has_key)
	{
		if(rev_mode) //server
			modes(port,dest,d_port,keyfile);
		else	//client
			modec(dest,d_port,keyfile);
		
	}
	return 0;
}

int modec(char *server_ip, char *d_port, char *keyfile) {//client
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	char *str=NULL;
	struct two *ptr = NULL;
	pthread_t rthread, wthread;
	int  iret1, iret2;
	char buffer[4096];
	portno = atoi(d_port);
	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}
	server = gethostbyname(server_ip);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	/* Now connect to the server */
	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR connecting");
		exit(1);
	}
   	ptr = (struct two*)malloc(sizeof(struct two));
	ptr->sock =0;
	ptr->sockfd=sockfd;
	ptr->keyfile = keyfile;
	iret1 = pthread_create( &wthread, NULL, w1fun, (void*)ptr);
	if(iret1)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret1);
		exit(EXIT_FAILURE);
	}

	iret2 = pthread_create( &rthread, NULL, r1fun, (void*)ptr);
	if(iret2)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret2);
		exit(EXIT_FAILURE);
	}
	//printf("pthread_create() for thread 1 returns: %d\n",iret1);
	//printf("pthread_create() for thread 2 returns: %d\n",iret2);

	pthread_join( wthread, NULL);
	pthread_join( rthread, NULL);
	close(sockfd);
	return 0;
}
void *w1fun( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct two *temp = (struct two*)ptr;
	int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}
	n = write(sockfd, iv, AES_BLOCK_SIZE);
	if (n <= 0) {
		perror("ERROR writing to socket");
		close(sockfd);
		free(str);
		exit(1);
	}
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		//fgets(buffer,4095,stdin);
		read(STDIN_FILENO, buffer, 4096);
		if(strlen(buffer) > 0)
		{
			fencrypt(buffer,str,(unsigned const char*)keyfile, iv);
			//printf("\n Encrypted message: %s\n",str);
			/* Send message to the server */
			n = write(sockfd, str, strlen(buffer));
			//printf("Sending the encrypted message to the pbproxy server side service\n");
			if (n <= 0) {
				perror("ERROR writing to socket");
				close(sockfd);
				free(str);
				exit(1);
			}
		}
	}
	free(str);
}
void *r1fun( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
    struct two *temp = (struct two*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	n = read(sockfd, iv, AES_BLOCK_SIZE);
	if (n <= 0) {
		perror("ERROR reading from socket");
		close(sockfd);
		free(str);
		exit(1);
	}
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sockfd, buffer, 4096);
		
		if (n <= 0) {
			perror("ERROR reading from socket");
			close(sockfd);
			free(str);
			exit(1);
		}
		//printf("Encrypted response received from pbproxy server side service: %s \n",buffer);
		fdecrypt(buffer,str,(unsigned const char*)keyfile, iv);
		//printf("Decrypted response: received from pbproxy server side service: ");
		strcat(str,"\0");
		//write(1, str, strlen(str));
		printf("%s",str);

	}
	free(str);
}
int modes( char *port,char *server_ip, char *d_port, char *keyfile) {
	int sockfd, newsockfd, portno, clilen;
	char buffer[4096];
	struct sockaddr_in serv_addr, cli_addr;
	int n, pid;

	/* First call to socket() function */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}
	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));
	//portno = 5001;//port
	portno = atoi(port);//pbproxy server port

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR on binding");
		exit(1);
	}

	/* Now start listening for the clients, here
	  * process will go in sleep mode and will wait
	  * for the incoming connection
	*/

	listen(sockfd,5);
	clilen = sizeof(cli_addr);
   
	while (1) 
	{
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0) {
			perror("ERROR on accept");
			exit(1);
		}
		/* Create child process */
		pid = fork();
		if (pid < 0) {
			perror("ERROR on fork");
			exit(1);
		}
		if (pid == 0) {
			/* This is the client process */
			close(sockfd);
			doprocessing(newsockfd,server_ip, d_port, keyfile);
			exit(0);
		}
		else {
			close(newsockfd);
		}

	} /* end of while */
}
void doprocessing (int sock,char *server_ip, char *d_port, char *keyfile) 
{
	int sockfd, portno, n;
	struct two *ptr = NULL;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	pthread_t rthread, wthread;
	int  iret1, iret2;

	portno = atoi(d_port);
	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}
	server = gethostbyname(server_ip);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);
   
	/* Now connect to the server */
	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR connecting");
		exit(1);
	}
	ptr = (struct two*)malloc(sizeof(struct two));
	ptr->sock =sock;
	ptr->sockfd=sockfd;
	ptr->keyfile = keyfile;
	iret1 = pthread_create( &wthread, NULL, w2fun, (void*) ptr);
	if(iret1)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret1);
		exit(EXIT_FAILURE);
	}

	iret2 = pthread_create( &rthread, NULL, r2fun, (void*) ptr);
	if(iret2)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret2);
		exit(EXIT_FAILURE);
	}
	//printf("pthread_create() for thread 1 returns: %d\n",iret1);
	//printf("pthread_create() for thread 2 returns: %d\n",iret2);

	pthread_join( wthread, NULL);
	pthread_join( rthread, NULL);
	free(ptr);
	close(sockfd);
	close(sock);
	return;
}
void *r2fun( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct two *temp = (struct two*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		close(sockfd);
		close(sock);
		//pthread_exit(NULL);
		exit(1);    
	}
	n = write(sock, iv, AES_BLOCK_SIZE);
	if (n <= 0) {
		close(sockfd);
		close(sock);
		perror("ERROR writing to socket");
		free(str);
		exit(1);
		//pthread_exit(NULL);
	}
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sockfd, buffer, 4096);
		if (n <= 0) {
			close(sockfd);
			close(sock);
			perror("ERROR reading from socket");
			free(str);
			exit(1);
			//pthread_exit(NULL);
		}

		//printf("\nHere is the response received from server: %s\n",buffer);
		//printf("Encrypting the response\n");
		//strcpy(buffer,"I got your message");
		bzero(str,4096);
		fencrypt(buffer,str,(unsigned const char*)keyfile, iv);
		//printf("Encrpted message: %s \n",str);
		//printf("Sending the encrypted message back to the pbproxy_client \n");
		n = write(sock,str,strlen(str));
		if (n <= 0) {
			close(sockfd);
			close(sock);
			perror("ERROR writing to socket");
			free(str);
			exit(1);
			//pthread_exit(NULL);
		}
	}
	free(str);
}
void *w2fun( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct two *temp = (struct two*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	n = read(sock, iv, AES_BLOCK_SIZE);
	if (n <= 0) {
		close(sockfd);
		close(sock);
		perror("ERROR reading from socket");
		free(str);
		exit(1);
		//pthread_exit(NULL);
	}

	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sock,buffer,4096);
		if (n <= 0) 
		{
			close(sockfd);
			close(sock);
			perror("ERROR reading from socket");
			free(str);
			exit(1);
			//pthread_exit(NULL);
		}
		//printf("\nHere is the encrypted message received from pbproxy_client: %s\n",buffer);
		fdecrypt(buffer,str,(unsigned const char*)keyfile, iv);
		//printf("Here is the decrypted message: %s\n",str);
		//printf("Sent the decrypted message to the server\n");
		//send this message(str) to the server and receive server's response here into buffer
		n = write(sockfd, str, strlen(buffer));
		if (n <= 0) {
			close(sockfd);
			close(sock);
			perror("ERROR writing to socket");
			free(str);
			exit(1);
			//pthread_exit(NULL);
		}
	}
	free(str);
}
int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void fencrypt(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv)
{ 
	int index=0;
	char temp[AES_BLOCK_SIZE];
	int i=0,j=0;
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }
	//printf("Enter the text to be encrypted :");
	//fgets(in_data,1023,stdin);
	init_ctr(&state, iv); //Counter call
	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext	
	for(i=0;in_data[i]!= '\0';i++)	
	{
		for(j=0;j<AES_BLOCK_SIZE && in_data[i]!='\0';j++)
		{
			temp[j]=in_data[i];
			i++;
		}
		i--;
		AES_ctr128_encrypt(temp, out_data+index, j , &key, state.ivec, state.ecount, &state.num);
		index+=j;
		if (j < AES_BLOCK_SIZE)
		{
			break;
		}
	}
}


void fdecrypt(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv)
{	
	//char in_data[1024];char out_data[1024];
	int index=0;
	char temp[AES_BLOCK_SIZE];
	int i=0,j=0;
	//Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }
	init_ctr(&state, iv);//Counter call
	//Encrypting Blocks of 16 bytes
	for(i=0;in_data[i]!= '\0';i++)	
	{
		//printf("\t i = %d",i);
		for(j=0;j<AES_BLOCK_SIZE && in_data[i]!='\0';j++)
		{
			temp[j]=in_data[i];
			i++;
		}
		i--;
		//printf("\t j = %d",j);
        //printf("%i\n", state.num);
		AES_ctr128_encrypt(temp, out_data+index, j, &key, state.ivec, state.ecount, &state.num);
        index+=j; 
		if (j < AES_BLOCK_SIZE) 
		{
			//printf("\nDecrypted text: ");
			//puts(out_data);
			break;
		}
	} 
}


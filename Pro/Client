#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>        //for struct ifreq
#include <pthread.h>

#define MAXMSGSIZE 256 
#define RANDOMSIZE 16  //size of random number
#define RSIZE 3		   //size limit of count r 
#define MACLENGTH 18   //length of MAC address

char recvBuf[MAXMSGSIZE+1];
char str[5];
int flag=0; //judge whether msg4 is lost
int clientSocket;
int Nonce;
char MAC[MACLENGTH];
char IV[MACLENGTH+8+32]; //MAC+Nonce+TK
char EncryptionKey[36];
char *filename;

int get_mac(char * mac, int len_limit)    //return value is the length of mac
{
    struct ifreq ifreq;
    int sock;

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror ("socket");
        return -1;
    }
    strcpy (ifreq.ifr_name, "ens33");    //my network card name is "ens33"

    if (ioctl (sock, SIOCGIFHWADDR, &ifreq) < 0)
    {
        perror ("ioctl");
        return -1;
    }
    
    return snprintf (mac, len_limit, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", (unsigned char) ifreq.ifr_hwaddr.sa_data[0], (unsigned char) ifreq.ifr_hwaddr.sa_data[1], (unsigned char) ifreq.ifr_hwaddr.sa_data[2], (unsigned char) ifreq.ifr_hwaddr.sa_data[3], (unsigned char) ifreq.ifr_hwaddr.sa_data[4], (unsigned char) ifreq.ifr_hwaddr.sa_data[5]);

}

void int2string(int num)
{
    int n,j;
    int i=0;
    char tmp[5];
    for(j=0;j<5;j++){tmp[j]='\0';str[j]='\0';}	
	
    if(num==0)
    {
	str[0]='0';
	str[1]='\0';
	return;
    }
    //printf("%d\n",num);
    n = num % 10;
    while (n>0)
    {
        tmp[i++] = n + '0';
        num = (num - n) / 10;
        n = num % 10;
    }
    tmp[i] = '\0';
    for (i=0; i<=strlen(tmp)-1; i++)
    {
        str[i] = tmp[strlen(tmp)-i-1];
    }
    str[i] = '\0';

}

void sendMsg(char *msg)
{
    if(send(clientSocket, msg, strlen(msg)+1, 0) < 0)	
    {
	printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
	return;
    }
    printf("     send msg: %s\n",msg);

}

void recvMsg()
{
	int n;
	//printf("here\n");
	memset(recvBuf,'\0',sizeof(recvBuf)-1);
	if((n=recv(clientSocket,recvBuf,MAXMSGSIZE,0))==-1)
	{
	    printf("recv msg error: %s(errno: %d)\n", strerror(errno), errno);
   	    exit(0);
	}
	recvBuf[n-1]='\0';
	
}

char *handshake(char *MasterKey)
{
	char sendBuf[MAXMSGSIZE+1];
	char ANonce[RANDOMSIZE+1];
	char CNonce[RANDOMSIZE+1]="";
	char CNonce_copy[RANDOMSIZE+1+RSIZE+1]="";
	unsigned char md[16];
	char tmp[3] = {'\0'}, TK[33] = {'0'};
	char *TK_;
	int i;
	int flag;
	char r[RSIZE+1]; 
	char autRequest[50]="Authentication_Request";
	while(1)
	{
		//1
		printf("-----------------------------------------------------\n");
		if(send(clientSocket, autRequest, strlen(autRequest), 0) < 0)
   		 {
   			 printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
   			 exit(0);
   		 }
		printf("     send msg: %s\n",autRequest);//send authentication request successfully
		
		//4
		printf("-----------------------------------------------------\n");
		recvMsg();
		printf("     recv msg: %s\n",recvBuf);
		memcpy(ANonce,recvBuf,RANDOMSIZE);
		ANonce[RANDOMSIZE]='\0';
		printf("       ANonce: %s\n",ANonce);
		memcpy(r,recvBuf+17,strlen(recvBuf)-17);
		r[strlen(recvBuf)-17]='\0';
		printf("            r: %s\n",r);
		srand(time(NULL));
    		for(i=0;i<RANDOMSIZE;i++)
   		{
			flag=(rand())%3;
			switch(flag)
			{
			case 0:
				CNonce[i] = rand()%26 + 'A'; 
				break;
			case 1:
				CNonce[i] = rand()%10 + '0'; 
				break;
			case 2:
				CNonce[i] = rand()%26 + 'a'; 
				break;
			}
    		}
		for(i=0;i<strlen(CNonce);i++) CNonce_copy[i]=CNonce[i];
		printf("       CNonce: %s\n",CNonce);
		printf("     MsterKey: %s\n",MasterKey);
	
		//5
		printf("-----------------------------------------------------\n");
		strcat(CNonce,MasterKey);
		strcat(ANonce,CNonce);
		//printf("%s\n",ANonce);
		MD5(ANonce,strlen(ANonce),md);
		for(i = 0;i < 16;i++)
		{
			sprintf(tmp, "%2.2x", md[i]);
			strcat(TK, tmp);
		}
		TK_=TK;
		printf("           TK: %s\n",TK);
	
		//6
		printf("-----------------------------------------------------\n");
		strcat(CNonce_copy,"&");	
		strcat(CNonce_copy,r);
		sendMsg(CNonce_copy);
	
		//9
		printf("-----------------------------------------------------\n");
		recvMsg();
		printf("     recv msg: %s\n",recvBuf);
		char ACK_[20]="Finish_Handshake";
		char ACK[20]="Get_CNonce&";
		int r_=atoi(r);
		r_++;
		int2string(r_);
		printf("          r+1: %s\n",str);
		strcat(ACK,str);
		if(strcmp(recvBuf,ACK)==0)
		{
			ACK[10]='\0';
			printf("     ACK:%s\n",ACK);
			strcat(ACK_,"&");
			strcat(ACK_,str);
			sendMsg(ACK_); //can be commented out as an msg4 loss test
		}
		printf("-----------------------------------------------------\n");
		printf("Handshake success!\n");
		printf("-----------------------------------------------------\n");
		//finish handshake
			break;
	}
	return TK_;
	
}

void *thread1(void)
{
	char done[5]="Done";
	while(1)
	{
		recvMsg();
		//no msg4 lost, finish listening
		if(strcmp(done,recvBuf)==0) return;		
		printf("     recv msg: %s\n",recvBuf);
		char r[RSIZE+1]={0};
		memcpy(r,recvBuf+11,strlen(recvBuf)-11);
		int r_=atoi(r);
		//printf("!!%d\n",r_);
		int2string(r_);
		char ACK_[20]="Finish_Handshake&";
		strcat(ACK_,str);
		sendMsg(ACK_);
		flag=1;
	}

}

void *thread2(void)
{
	unsigned char md[16];
	char tmp[3] = {'\0'}, streamKey[33] = {'0'};
	int i;
	FILE *fp=NULL;
	char msgBuff[17];
	char cipherText[17]={'0'};
	char highByte,lowByte;
	char key[17];
	fp=fopen(filename,"r");

	sleep(1); //send msg4, so delay 1 second
	while(1)
	{	
		//client had sent a new msg4
		if(flag==1)
		{
			flag=0;
			Nonce=0;
			sleep(1); //wait ap to initialize
		}
				
		memset(streamKey,'\0',sizeof(streamKey));
		int2string(Nonce);
		memset(IV,'\0',sizeof(IV));
		strcpy(IV,MAC);
		//printf("%s\n",IV);
		strcat(IV,str);
		//printf("%s\n",IV);
		strcat(IV,EncryptionKey);
		//printf("%s\n",IV);

		MD5(IV,strlen(IV),md);
		for(i = 0;i < 16;i++)
		{
			sprintf(tmp, "%2.2x", md[i]);
			strcat(streamKey, tmp);
		}
		//encrypt and send plaintext	
		memset(msgBuff,'\0',sizeof(msgBuff));		
		fgets(msgBuff,17,(FILE *)fp);
		if(msgBuff[0]=='\0'||msgBuff[0]=='\n') break;
		//printf("        Nonce: %s\n",str);
		//printf("        IV+TK: %s\n",IV);
		printf("    streamKey: %s\n",streamKey);
		//padding
		if(msgBuff[15]=='\0')
		{
			for(i=0;i<16;i++) if(msgBuff[i]=='\0'||msgBuff[i]=='\n') msgBuff[i]='0';
		}
		printf("    plaintext: %s\n",msgBuff);

		memset(cipherText,'\0',sizeof(cipherText));
		for(i=0;i<strlen(streamKey);i+=2)
		{
			highByte=streamKey[i];
			lowByte=streamKey[i+1];

			if(highByte > 0x39)//letter
				highByte-=0x57;
			else 			   //figure
				highByte-=0x30;

			if(lowByte > 0x39)//letter
				lowByte-=0x57;
			else 			  //figure
				lowByte-=0x30;
			
			key[i/2]=(highByte<<4)|lowByte;
		}
		key[17]='\0';	
		//printf("          key: %s\n",key);
		for(i=0;i<strlen(msgBuff);i++)
		{
			cipherText[i]=key[i]^msgBuff[i];
		}
		cipherText[i]='\0';
		printf("   cipherText: %s\n",cipherText);
		/*for(i = 0;i < 16;i++)
		{
			sprintf(tmp, "%2.2x", msgBuff[i]);
			strcat(cipherText, tmp);
		}
		for(i=0;i<strlen(cipherText);i++) cipherText[i]^=streamKey[i];
		printf("%s\n",cipherText);*/		
		sendMsg(cipherText);
		sleep(1);
		Nonce++;
		printf("-----------------------------------------------------\n");	
	}
}

void encryptTransmission()
{
	//printf("%s\n",EncryptionKey);
	int nRtn=get_mac(MAC, sizeof(MAC));
	if(nRtn > 0)
        {
        	fprintf(stderr, "  MAC address: %s\n", MAC);
        }
	printf("-----------------------------------------------------\n");
	
	pthread_t id1,id2; //two threads
	int res;
	
	//listen ap for a new msg3
	res=pthread_create(&id1,NULL,(void *)thread1,NULL);
	if(res) printf("Thread1 create error!\n");

	//encrypt data and send them
	res=pthread_create(&id2,NULL,(void *)thread2,NULL);
	if(res) printf("Thread2 create error!\n");
	
	pthread_join(id2,NULL); //only wait thread 2 to quit

	//data transmission is done, send a last packet
	char *done="Done!";
	sendMsg(done);

	printf("-----------------------------------------------------\n");
	printf("Finish data transmission!\n");
	printf("-----------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	//char *Nonce_padding="0";
	char *EncryptionKey_;
	int i;
	struct sockaddr_in apAddr; //AP network address structure
	memset(&apAddr,0,sizeof(apAddr)); //initialize
	apAddr.sin_family=AF_INET; //set as IP communication
	apAddr.sin_addr.s_addr=inet_addr(argv[1]);//server IP address
	apAddr.sin_port=htons(atoi(argv[2])); //server port
	
	//create client socket
	if((clientSocket=socket(PF_INET,SOCK_STREAM,0))<0)
	{
		perror("client socket create error");
		return 1;
	}
	
	//connect client socket to server socket network address
	if(connect(clientSocket,(struct sockaddr *)&apAddr,sizeof(struct sockaddr))<0)
	{
		perror("client socket connect error");
		return 1;
	}
	printf("connected to server\n");
	
    	//WPA2
	//4 handshake steps stage
	EncryptionKey_=handshake(argv[3]);
	for(i=0;i<36;i++) EncryptionKey[i]=*(EncryptionKey_+i); 
	printf("EncryptionKey: %s\n",EncryptionKey);
	Nonce=0;
	int2string(Nonce);
	/*for(i=0;i<(7-strlen(str));i++) strcat(Nonce_padding,"0");
	strcat(Nonce_padding,Nonce);*/
	printf("        Nonce: %s\n",str);
	
	//data transmission stage
	filename=argv[4];
	encryptTransmission();
	
	//close client socket
	close(clientSocket);
    
	return 0;
}

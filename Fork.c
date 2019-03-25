#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //sleep

void main(){
   printf("\n parent pid:%d",(int)getpid());
   system("ping 192.168.1.71 -c 1");    
}
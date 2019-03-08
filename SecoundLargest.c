#include<stdio.h>

void main(){

 int a[] = {1,5,3,4,6,782,67,6,1};
 int largest = 0;
 int secound_L = 0;
 largest = a[0];

 int size = sizeof(a) /sizeof(a[0]);
 
 for(int i=0; i < size ; i++ ){

      if( a[i] > largest){
          secound_L = largest;
          largest = a[i];
       }
       else if(secound_L < a[i])
         secound_L = a[i];
 }

 printf("SL: %d, L:%d \n",secound_L, largest);

}

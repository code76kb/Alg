#include <stdio.h>

void main(){
  int a = 13;
  int b =  25;
  printf("a: %d\nb: %d \n",a,b);
  a = a+b;
  b = a-b;
  a = a-b;
  printf("After Swip a: %d\nb: %d \n",a,b);
}

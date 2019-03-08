#include<stdio.h>
#include<stdlib.h>

void main(){

int A_Row = 10;
int A_Column = rand() % 10;

int a[A_Row];

int sorted[A_Row];

printf("A :(%d,%d)\n\n",A_Row,A_Column);

// Initilize
  for(int i=0; i < A_Row; i++ ){
     a[i] = rand()%50;
     printf("%d,",a[i]);
  }

//Sort
int tmp=0;
for(int i=0; i < A_Row; i++){


 }

//Show
printf("\n sorted...");
for(int i=0; i < A_Row; i++ ){
   printf("%d,",a[i]);
}


}

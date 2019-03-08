#include<stdio.h>


void main(){

   int rokda = 0;
   int baca = 0;
   int notes[] = {1000,500,100,50,20,10,5,2,1};
   int noteCount[] = {0,0,0,0,0,0,0,0,0};

   printf("Rokdaa batawo ..");
   scanf("%d",&rokda);

   baca = rokda;

   for (int i=0; i<9; i++ ){

     if(baca >= notes[i]){
      noteCount[i]  = (int) baca/notes[i];
      baca = baca%notes[i];
     }

   }

   for(int i=0; i<9; i++){
     printf("%d'X'%d\n", notes[i],noteCount[i]);
   }
}

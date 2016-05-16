#include <stdio.h>
#include <string.h>

#define KEY "key{ThisCouldBeYourReallyLongAssKeyHolyShitThisIsLong}"
#define MAX_INPUT_LEN 512

// Simple string comparison without strcmp
int main(int argc, char *argv[]) {
   int i = 0;
   char buf[MAX_INPUT_LEN + 1];

   bzero(buf, MAX_INPUT_LEN + 1); 
   fread(buf, 1, MAX_INPUT_LEN, stdin);

   if(!strncmp(KEY, buf, strlen(KEY))) {
         printf("You win with the key: %s\n", KEY);
   } else {
      printf("You lose!\n");
   }
}

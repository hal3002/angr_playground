#include <stdio.h>
#include <string.h>

#define KEY "key{ThisCouldBeYourReallyLongAssKeyHolyShitThisIsLong}"

// Simple string comparison without strcmp
int main(int argc, char *argv[]) {
   int i = 0;

   if(argc != 2) {
      fprintf(stderr, "Usage: %s <key>", argv[0]);
      return 0;
   }

   if(!strncmp(KEY, argv[1], strlen(KEY))) {
         printf("You win with the key: %s\n", KEY);
   } else {
      printf("You lose!\n");
   }
}

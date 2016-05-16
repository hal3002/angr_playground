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

   if(strlen(KEY) == strlen(argv[1])) {
      for(i = 0; i < strlen(KEY); i++) {
         if(KEY[i] != argv[1][i]) {
            break;
         }
      }

      if(i == strlen(KEY)) {
         printf("You win with the key: %s\n", KEY);
         return 0;
      }
   }
   printf("You lose!\n");
}

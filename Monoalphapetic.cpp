#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define ALPHABET_SIZE 26
void encrypt(char plaintext[], char substitutionKey[]) {
    int length = strlen(plaintext);
    
    for (int i = 0; i < length; i++) {
        if (isalpha(plaintext[i])) {
            char originalChar = tolower(plaintext[i]);
            int index = originalChar - 'a';
            
            if (isupper(plaintext[i])) {
                plaintext[i] = toupper(substitutionKey[index]);
            } else {
                plaintext[i] = substitutionKey[index];
            }
        }
    }
}
int main() {
    char plaintext[100];
     
    
    printf("Enter the plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    
    if (strlen(plaintext) > 0 && plaintext[strlen(plaintext) - 1] == '\n') {
        plaintext[strlen(plaintext) - 1] = '\0';
    }
    
    
    
    printf("Ciphertext: %s\n", plaintext);
    
    return 0;
}

	

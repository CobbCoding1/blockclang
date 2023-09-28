#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

unsigned char *create_sha256(const unsigned char str[], unsigned char *buffer){
    SHA256(str, strlen((const char*)str), buffer);
    return buffer;
}
/*
int main(){
    const unsigned char str[] = "123";
    unsigned char *buffer = malloc(sizeof(char) * SHA256_DIGEST_LENGTH);
    buffer = create_sha256(str, buffer);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        printf("%02hhX", buffer[i]);
    }
    printf("\n");
}
*/

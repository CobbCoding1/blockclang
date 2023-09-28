#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "crypto.h"

#define BLOCKCHAIN_MAX_LENGTH 16

typedef struct{
  unsigned char *hash;  
  struct MerkelNode *left;
  struct MerkelNode *right;
} MerkelNode;

typedef struct{
    size_t index;
    time_t timestamp;
    int nonce;
    unsigned char *hash;
    unsigned char *prev_hash;
} Block;

unsigned char *hash_block(Block block){
    unsigned char *block_record = malloc(sizeof(char) * 1024);
    sprintf((char*)block_record, "%zu %ld %i %s", block.index, block.timestamp, block.nonce, (char*)block.prev_hash);
    unsigned char *buffer = malloc(sizeof(char) * SHA256_DIGEST_LENGTH);
    buffer = create_sha256((const unsigned char*)block_record, buffer);
    return buffer; 
}

Block generate_block(Block old_block, int nonce){
    Block block;

    block.index = old_block.index + 1;
    block.timestamp = time(NULL);
    block.nonce = nonce;
    block.prev_hash = old_block.hash;
    block.hash = hash_block(block);

    return block;
}

bool is_valid_block(Block old_block, Block block){
    if((old_block.index + 1) != block.index){
        printf("INDEX NOT VALID\n");
        return false;
    }

    char hash1[SHA256_DIGEST_LENGTH];
    char hash2[SHA256_DIGEST_LENGTH];

    strcpy(hash1, (char*)old_block.hash);
    strcpy(hash2, (char*)block.hash);

    if(memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0){
        printf("OLD HASH NOT VALID\n");
        return false;
    }

    strcpy(hash1, (char*)hash_block(block));
    strcpy(hash2, (char*)block.hash);

    if(memcmp(hash1, hash2, SHA256_DIGEST_LENGTH - 16) == 0){
        printf("NEW HASH NOT VALID\n");
        return false;
    }

    return true;
}

Block *replace_chain(Block new_blockchain[BLOCKCHAIN_MAX_LENGTH], Block old_blockchain[BLOCKCHAIN_MAX_LENGTH]){
    int new_len = 0;
    int old_len = 0;

    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; i++){
        if(new_blockchain[i].index != i){
            break;
        }
        new_len++;
    }

    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; i++){
        if(old_blockchain[i].index != i){
            break;
        }
        old_len++;
    }

    if(new_len > old_len){
        printf("REPLACING BLOCKCHAIN\n");
        return new_blockchain;
    } else {
        printf("CURRENT BLOCKCHAIN IS LONGER\n");
        return old_blockchain;
    }
}

void print_block(Block block){
    printf("INDEX: %zu\n", block.index);
    printf("TIMESTAMP: %ld\n", block.timestamp);
    printf("NONCE: %i\n", block.nonce);
    if(block.prev_hash == NULL){
        printf("PREV HASH: NULL\n");
    } else {
        printf("PREV HASH: ");
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
            if(block.prev_hash != NULL){
                printf("%02hhX", block.prev_hash[i]);
            }
        }
        printf("\n");
    }
    printf("HASH: ");
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        printf("%02hhX", block.hash[i]);
    }
    printf("\n");
}

void print_blockchain(Block blockchain[BLOCKCHAIN_MAX_LENGTH]){
    for(int i = 0; i < BLOCKCHAIN_MAX_LENGTH; i++){
        if(blockchain[i].index != (size_t)i){
            break;
        }
        print_block(blockchain[i]);
        if(i != 0){
            printf("IS VALID: %d\n", is_valid_block(blockchain[i-1], blockchain[i]));
        }
        printf("\n\n");
    }
}

int main(){
    Block blockchain[BLOCKCHAIN_MAX_LENGTH];
    Block blockchain2[BLOCKCHAIN_MAX_LENGTH];
    Block root_block;
    root_block.index = 0;
    root_block.timestamp = time(NULL);
    root_block.nonce = 0;
    root_block.prev_hash = NULL;
    root_block.hash = hash_block(root_block);
    blockchain[root_block.index] = root_block;
    blockchain2[root_block.index] = root_block;

    Block block1 = generate_block(root_block, root_block.nonce + 1);
    Block block2 = generate_block(block1, block1.nonce + 1);
    Block block3 = generate_block(block2, block2.nonce + 1);
    Block block4 = generate_block(block3, block3.nonce + 1);
    Block block5 = generate_block(block4, block4.nonce + 1);
    Block block6 = generate_block(block5, block5.nonce + 1);
    blockchain[block1.index] = block1;
    blockchain[block2.index] = block2;
    blockchain[block3.index] = block3;
    blockchain[block4.index] = block4;
    blockchain[block5.index] = block5;


    blockchain2[block1.index] = block1;
    blockchain2[block2.index] = block2;
    blockchain2[block3.index] = block3;
    blockchain2[block4.index] = block4;
    blockchain2[block5.index] = block5;
    blockchain2[block6.index] = block6;
    print_blockchain(blockchain);
    replace_chain(blockchain2, blockchain);
}

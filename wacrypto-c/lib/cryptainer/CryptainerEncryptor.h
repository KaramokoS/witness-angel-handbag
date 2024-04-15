#ifndef CryptainerEncryptor_H
#define CryptainerEncryptor_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CRYPTAINER_FORMAT "example_format"

// Define data structures
struct SymmetricKey {
    char cipher_algo[100];
};

typedef struct PayloadCipherLayer PayloadCipherLayer;
struct PayloadCipherLayer {
    char payload_cipher_algo[100];
    char* payload_macs; // will be filled later
    char key_ciphertext[100]; // assuming key ciphertext is a string for simplicity
    char symmetric_key[100]; // assuming symmetric key is a string for simplicity
    char payload_digest_algos[10][100];
    char payload_signatures[100];
    char key_cipher_layers[100];
};

typedef struct Cryptainer Cryptainer;
struct Cryptainer {
    char cryptainer_state[100];
    char cryptainer_format[100];
    char cryptainer_uid[100];
    char keychain_uid[100];
    char* payload_ciphertext_struct; // will be filled later
    PayloadCipherLayer payload_cipher_layers[100];
    char* cryptainer_metadata; // assuming cryptainer metadata is a string for simplicity
};

typedef struct PayloadEncryptionPipeline PayloadEncryptionPipeline;
struct PayloadEncryptionPipeline {
    char* output_stream;
    char* cipher_streams;
};
typedef struct wa_CryptainerEncryptor wa_CryptainerEncryptor;

struct wa_CryptainerEncryptor
{
    struct Cryptainer cryptainer;
    struct PayloadCipherLayer payload_cipher_layer_extracts;
    struct PayloadEncryptionPipeline payload_encryption_pipeline;
};

typedef struct cryptoconf cryptoconf;
void wa_CryptainerEncryptor_init(wa_CryptainerEncryptor* const self);  
void wa_CryptainerEncryptor_cleanup(wa_CryptainerEncryptor* const self);  

wa_CryptainerEncryptor * wa_CryptainerEncryptor_create(void); 
void wa_CryptainerEncryptor_destroy(wa_CryptainerEncryptor* const self); 

void wa_build_cryptainer_and_encryption_pipeline(wa_CryptainerEncryptor* const self, cryptoconf* const m_cryptoconf, char **output_stream, char **cryptainer_metadata);
int wa_CryptainerEncryptor_encryptData(wa_CryptainerEncryptor* const self, char* payload, char* cryptoconf, char* cryptainer_metadata);

#endif
#include "CryptainerEncryptor.h"
#include "cipher.c"

uint8_t* crypt(const char *input, uint8_t *key, uint8_t *iv);

char* wa_generate_uuid0(void);

char* wa_generate_symkey(const char*);

char* wa_encrypt_key_through_multiple_layers(const char*, const char*, const char*, const char*);

void wa_deepcopy_dict(const struct Cryptainer*, struct Cryptainer*);

struct SymmetricKey* wa_generate_cryptainer_base_and_secrets(const char*, const char*);

void wa_CryptainerEncryptor_init(wa_CryptainerEncryptor* const self)
{
    // init here
}

void wa_CryptainerEncryptor_cleanup(wa_CryptainerEncryptor* const self)
{
    // cleanup here
}  

int wa_CryptainerEncryptor_encryptData(wa_CryptainerEncryptor* const self, char* payload, char* cryptoconf, char* cryptainer_metadata)
{
    char *iv = "some random val" 
    char *keys[] = {"first", "second", "third"};
    unsigned char encrypted_data;
    do {
        crypt(encrypted_data, *keys, iv);
        keys++
    } while(keys != NULL)
}

wa_CryptainerEncryptor * wa_CryptainerEncryptor_create(void); 
void wa_CryptainerEncryptor_destroy(wa_CryptainerEncryptor* const self); 

void wa_build_cryptainer_and_encryption_pipeline(wa_CryptainerEncryptor* const self, cryptoconf* const m_cryptoconf, char **output_stream, char **cryptainer_metadata)
{
  char* cryptainer, char* payload_cipher_layer_extracts = wa_generate_cryptainer_base_and_secrets(m_cryptoconf, cryptainer_metadata);
  char* encryption_pipeline = PayloadEncryptionPipeline(output_stream, payload_cipher_layer_extracts);
}


struct SymmetricKey* wa_generate_cryptainer_base_and_secrets(const char* cryptoconf, const char* cryptainer_metadata) {
    // Assuming cryptoconf and cryptainer_metadata are JSON strings

    // Check if cryptainer_metadata is NULL or a dictionary
    if (cryptainer_metadata != NULL && strlen(cryptainer_metadata) == 0) {
        printf("Error: cryptainer_metadata is empty or not a dictionary\n");
        exit(EXIT_FAILURE);
    }

    // Initialize variables
    struct Cryptainer cryptainer;
    struct SymmetricKey* payload_cipher_layer_extracts = NULL;

    char* cryptainer_uid = wa_generate_uuid0();

    char* default_keychain_uid = NULL;

    // Deep copy cryptoconf to cryptainer
    wa_deepcopy_dict((struct Cryptainer*)cryptoconf, &cryptainer);

    if (cryptainer.payload_cipher_layers == NULL || strlen(cryptainer.payload_cipher_layers) == 0) {
        printf("Error: Empty payload_cipher_layers list is forbidden in cryptoconf\n");
        exit(EXIT_FAILURE);
    }

    // Iterate through payload_cipher_layers
    for (int i = 0; i < sizeof(cryptainer.payload_cipher_layers) / sizeof(cryptainer.payload_cipher_layers[0]); i++) {

        struct PayloadCipherLayer payload_cipher_layer = cryptainer.payload_cipher_layers[i];

        char* symkey = wa_generate_symkey(payload_cipher_layer.payload_cipher_algo);

        // Encrypt key through multiple layers
        char* key_ciphertext = wa_encrypt_key_through_multiple_layers(default_keychain_uid, symkey, payload_cipher_layer.key_cipher_layers, cryptainer_metadata);

        // Update payload_cipher_layer
        strcpy(payload_cipher_layer.symkey.cipher_algo, payload_cipher_layer.payload_cipher_algo);
        strcpy(payload_cipher_layer.symkey.symmetric_key, symkey);
        for (int j = 0; j < sizeof(payload_cipher_layer.payload_digest_algos) / sizeof(payload_cipher_layer.payload_digest_algos[0]); j++) {
            strcpy(payload_cipher_layer.symkey.payload_digest_algos[j], payload_cipher_layer.payload_digest_algos[j]);
        }
        strcpy(payload_cipher_layer.key_ciphertext, key_ciphertext);

        payload_cipher_layer_extracts = realloc(payload_cipher_layer_extracts, (i + 1) * sizeof(struct SymmetricKey));
        payload_cipher_layer_extracts[i] = payload_cipher_layer.symkey;
    }

    // Update cryptainer fields
    strcpy(cryptainer.cryptainer_state, "STARTED");
    strcpy(cryptainer.cryptainer_format, CRYPTAINER_FORMAT);
    strcpy(cryptainer.cryptainer_uid, cryptainer_uid);
    strcpy(cryptainer.keychain_uid, default_keychain_uid);
    cryptainer.payload_ciphertext_struct = NULL; // Must be filled asap
    cryptainer.cryptainer_metadata = cryptainer_metadata;

    return payload_cipher_layer_extracts;
}


char* wa_generate_uuid0() {
    return "example_uuid";
}

char* wa_generate_symkey(const char* cipher_algo) {
    return "example_symmetric_key";
}

char* wa_encrypt_key_through_multiple_layers(const char* default_keychain_uid, const char* key_bytes, const char* key_cipher_layers, const char* cryptainer_metadata) {
    return "example_key_ciphertext";
}

void wa_deepcopy_dict(const struct Cryptainer* source, struct Cryptainer* destination) {
    strcpy(destination->cryptainer_state, source->cryptainer_state);
    strcpy(destination->cryptainer_format, source->cryptainer_format);
    strcpy(destination->cryptainer_uid, source->cryptainer_uid);
    strcpy(destination->keychain_uid, source->keychain_uid);
    destination->payload_ciphertext_struct = NULL; // Assuming pointer is initialized to NULL
    destination->cryptainer_metadata = source->cryptainer_metadata; // Shallow copy for simplicity
}


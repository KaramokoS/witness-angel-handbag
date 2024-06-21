#include "CryptainerEncryptor.h"
#include "cipher.c"
#include "cJSON.h"
#include "lwjson.h"
#include <stdbool.h>


void wa_dump_to_json_bytes(unsigned char* key_cipherdict, unsigned char* key_bytes);

uint8_t* crypt(const char *input, uint8_t *key, uint8_t *iv);

void wa_generate_uuid0(char*);

char* wa_generate_symkey(const char*);

int wa_encrypt_bytestring(char* key_bytes, char* key_cipher_algo, char* sub_symkey[], Ciphertext* key_cipherdict);
int wa_encrypt_key_with_asymmetric_cipher(
                                    char* cipher_algo, 
                                    char* keychain_uid, 
                                    char* key_bytes, 
                                    char** trustee,
                                    char** cryptainer_metadata,
                                    Ciphertext* key_cipherdict
);
void wa_encrypt_key_through_single_layer(const char*, const char*, KeyCipherLayer*, const char*, char*);
char* wa_encrypt_key_through_multiple_layers(const char*, const char*, KeyCipherLayer*[], size_t, const char*);

void wa_deepcopy_dict(const struct Cryptainer*, struct Cryptainer*);

void wa_generate_cryptainer_base_and_secrets(wa_CryptainerEncryptor* const self, const char*, const char*);

Shard* wa_split_secret_into_shards(const uint8_t* secret, size_t secret_len, int shard_count, int threshold_count, int* full_shards_count);

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
        keys++;
    } while(keys != NULL);
}

wa_CryptainerEncryptor * wa_CryptainerEncryptor_create(void); 
void wa_CryptainerEncryptor_destroy(wa_CryptainerEncryptor* const self); 

void wa_build_cryptainer_and_encryption_pipeline(wa_CryptainerEncryptor* const self, cryptoconf* const m_cryptoconf, char **output_stream, char **cryptainer_metadata)
{
  wa_generate_cryptainer_base_and_secrets(self, m_cryptoconf, cryptainer_metadata);
  Cryptainer cryptainer = self->cryptainer; 
  PayloadCipherLayer payload_cipher_layer_extracts = self->payload_cipher_layer;
  PayloadEncryptionPipeline encryption_pipeline;
  encryption_pipeline.output_stream = output_stream;
  encryption_pipeline.cipher_streams = NULL; /* retrieve cipher_stram*/;
  self->payload_encryption_pipeline = encryption_pipeline;
}


void wa_generate_cryptainer_base_and_secrets(wa_CryptainerEncryptor* const self, const char* cryptoconf, const char* cryptainer_metadata) {
    // Assuming cryptoconf and cryptainer_metadata are JSON strings

    // Check if cryptainer_metadata is NULL or a dictionary
    if (cryptainer_metadata != NULL && strlen(cryptainer_metadata) == 0) {
        printf("Error: cryptainer_metadata is empty or not a dictionary\n");
        exit(EXIT_FAILURE);
    }

    // Initialize variables
    Cryptainer cryptainer;
    memset(&cryptainer, 0, sizeof(Cryptainer));

    char cryptainer_uid[MAX_UID_LENGTH];
    wa_generate_uuid0(cryptainer_uid);

    static lwjson_token_t tokens[128];
    static lwjson_t lwjson;
    lwjson_init(&lwjson, tokens, LWJSON_ARRAYSIZE(tokens));

    char default_keychain_uid[MAX_UID_LENGTH];

    if (lwjson_parse(&lwjson, cryptoconf) == lwjsonOK) {
        const lwjson_token_t* tkn;
        printf("JSON parsed..\r\n");

        /* Find custom key in JSON */
        tkn = lwjson_find_ex(&lwjson, NULL, "keychain_uid.$binary.base64");
        if(tkn->u.str.token_value_len < MAX_UID_LENGTH) {
            strncpy(default_keychain_uid, strndup(tkn->u.str.token_value, (int)tkn->u.str.token_value_len), tkn->u.str.token_value_len);
            default_keychain_uid[tkn->u.str.token_value_len+1] = '\0';
        } else {
            printf("Error: keychain uid length is greater MAX_UID_LENGTH\n");
            exit(EXIT_FAILURE);
        }

        lwjson_free(&lwjson);
    }


    if(default_keychain_uid[0] == '\0') {
        wa_generate_uuid0(default_keychain_uid);
    }

    // Deep copy cryptoconf to cryptainer
    wa_deepcopy_dict((struct Cryptainer*)cryptoconf, &cryptainer);

    if (cryptainer.payload_cipher_layers == NULL || strlen(cryptainer.payload_cipher_layers) == 0) {
        printf("Error: Empty payload_cipher_layers list is forbidden in cryptoconf\n");
        exit(EXIT_FAILURE);
    }

    size_t paload_cipher_layers_count = sizeof(cryptainer.payload_cipher_layers) / sizeof(cryptainer.payload_cipher_layers[0]);
    PayloadCipherLayer* payload_cipher_layer_extracts = malloc(paload_cipher_layers_count * sizeof(PayloadCipherLayer));
    // Iterate through payload_cipher_layers
    for (size_t i = 0; i < paload_cipher_layers_count; i++) {

        struct PayloadCipherLayer payload_cipher_layer = cryptainer.payload_cipher_layers[i];

        char* symkey = wa_generate_symkey(payload_cipher_layer.payload_cipher_algo);

        // Encrypt key through multiple layers
        size_t key_cipher_layers_length = sizeof(payload_cipher_layer.key_cipher_layers) / sizeof(payload_cipher_layer.key_cipher_layers[0]);
        char* key_ciphertext = wa_encrypt_key_through_multiple_layers(default_keychain_uid, symkey, payload_cipher_layer.key_cipher_layers, key_cipher_layers_length, cryptainer_metadata);

        // Update payload_cipher_layer
        strcpy(payload_cipher_layer.symmetric_key, symkey);
        for (int j = 0; j < sizeof(payload_cipher_layer.payload_digest_algos) / sizeof(payload_cipher_layer.payload_digest_algos[0]); j++) {
            strcpy(payload_cipher_layer.payload_digest_algos[j], payload_cipher_layer.payload_signatures[j]);
        }
        strcpy(payload_cipher_layer.key_ciphertext, key_ciphertext);

        payload_cipher_layer_extracts[i] = payload_cipher_layer;

        free(symkey);
        free(key_ciphertext);
    }

    // Update cryptainer fields
    strcpy(cryptainer.cryptainer_state, "STARTED");
    strcpy(cryptainer.cryptainer_format, CRYPTAINER_FORMAT);
    strcpy(cryptainer.cryptainer_uid, cryptainer_uid);
    strcpy(cryptainer.keychain_uid, default_keychain_uid);
    cryptainer.payload_ciphertext_struct = NULL; // Must be filled asap
    cryptainer.cryptainer_metadata = cryptainer_metadata;
    
    self->cryptainer = cryptainer;
    memcpy(&self->payload_cipher_layer_extracts, payload_cipher_layer_extracts, paload_cipher_layers_count * sizeof(PayloadCipherLayer));
    free(payload_cipher_layer_extracts);
    free(default_keychain_uid);
}


void wa_generate_uuid0(char* key_chain) {
    strncpy(key_chain, "example_uuid", MAX_UID_LENGTH);
}

char* wa_generate_symkey(const char* cipher_algo) {
    return "example_symmetric_key";
}

char* wa_encrypt_key_through_multiple_layers(const char* default_keychain_uid, 
                                            const char* key_bytes, 
                                            KeyCipherLayer* key_cipher_layers[],
                                            size_t key_cipher_layers_length, 
                                            const char* cryptainer_metadata) {
    
    Ciphertext key_cipherdict[MAX_KEY_BYTES_LENGTH];
    const char key_bytes_initial[MAX_KEY_BYTES_LENGTH];
    strcpy(key_bytes_initial, key_bytes);

    if(key_cipher_layers_length == 0) {
        printf("Empty key_cipher_layers list is forbidden in cryptoconf\n");
        exit(EXIT_FAILURE);
    }
    
    for (size_t i = 0; i < key_cipher_layers_length; i++) {
        wa_encrypt_key_through_single_layer(
            default_keychain_uid,
            key_bytes,
            key_cipher_layers[i],
            cryptainer_metadata,
            key_cipherdict
        );
        wa_dump_to_json_bytes(key_cipherdict, key_bytes);  // Thus its remains as bytes all along
    }

    assert(strcmp((char*)key_bytes, (char*)key_bytes_initial) != 0);  // safety

    return key_bytes;
}
bool is_supported_algorithm(const char* algo, const char* supported_algos[], int count) {
    for (int i = 0; i < count; ++i) {
        if (strcmp(algo, supported_algos[i]) == 0) {
            return true;
        }
    }
    return false;
} 
void wa_encrypt_key_through_single_layer(const char* default_keychain_uid, 
                                        const char* key_bytes, KeyCipherLayer* key_cipher_layers, 
                                        const char* cryptainer_metadata, Ciphertext* key_cipherdict) {
    assert(key_bytes != NULL);
    const char key_cipher_algo[MAX_KEY_BYTES_LENGTH];
    strcpy(key_cipher_algo, key_cipher_layers->key_cipher_algo);
    size_t supported_sym_key_count = sizeof(SUPPORTED_SYMMETRIC_KEY_ALGOS) / sizeof(SUPPORTED_SYMMETRIC_KEY_ALGOS[0]);
    if(strcmp(key_cipher_algo, &SHARED_SECRET_ALGO_MARKER) == 0) {
        char key_shared_secret_shards[sizeof(key_cipher_layers->u.key_shared_secret_shards)];
        strcpy(key_shared_secret_shards, key_cipher_layers->u.key_shared_secret_shards);
        size_t shard_count = sizeof(key_shared_secret_shards) / sizeof(key_shared_secret_shards);
        size_t threshold_count = key_cipher_layers->u.key_shared_secret_threshold;
        if(!(0 < threshold_count && threshold_count <= shard_count)) {
            printf("Shared secret threshold must be strictly positive and not greater than shard count, in cryptoconf");
            exit(EXIT_FAILURE);
        }
        int full_shards_count;
        Shard* shards = wa_split_secret_into_shards((const uint8_t*)key_bytes, strlen(key_bytes), shard_count, threshold_count, &full_shards_count);
        size_t shards_length = sizeof(shards->data) / shards->data[0];
        if(shards_length != shard_count) {
            printf("shards_length != shard_count");
            exit(EXIT_FAILURE);
            //stderr();
        }

        //TODO: right memory amount Ciphertext* shard_ciphertexts = (Ciphertext*)malloc(num_shards * sizeof(Ciphertext));

        for (int i = 0; i < shard_count; ++i) {
            Shard shard = shards[i];
            KeyCipherLayer key_shared_secret_shard_conf = key_cipher_layers[i];

            size_t shard_bytes_len;
            uint8_t* shard_bytes;
            wa_dump_to_json_bytes(shard_bytes, (char*)shard.data);
            
            size_t shard_ciphertext_len;
            uint8_t* shard_ciphertext = wa_encrypt_key_through_multiple_layers(
                default_keychain_uid,
                shard_bytes,
                &key_shared_secret_shard_conf,
                shard_bytes_len,
                cryptainer_metadata
            );
            
            assert(shard_ciphertext != NULL);

            key_cipherdict[i].ciphertext = shard_ciphertext;
            key_cipherdict[i].ciphertext_len = shard_ciphertext_len;

            free(shard_bytes);
        }
    } else if (is_supported_algorithm(key_cipher_algo, SUPPORTED_SYMMETRIC_KEY_ALGOS,supported_sym_key_count)) 
    {
        size_t supported_cipher_algo_count = sizeof(SUPPORTED_CIPHER_ALGOS) / sizeof(SUPPORTED_CIPHER_ALGOS[0]);
        if(is_supported_algorithm(key_cipher_algo, SUPPORTED_CIPHER_ALGOS, supported_cipher_algo_count)) {
            printf("%s is a SIGNATURE algo", &key_cipher_algo);
            exit(EXIT_FAILURE);
        }
        // logger instead
        printf("Generating symmetric subkey of type %s for key encryption", &key_cipher_algo);
        char* sub_symkey = wa_generate_symkey(&key_cipher_algo);
        char* sub_symkey_bytes[MAX_KEY_BYTES_LENGTH];
        wa_dump_to_json_bytes(sub_symkey_bytes, sub_symkey);

        uint8_t* sub_symkey_ciphertext = wa_encrypt_key_through_multiple_layers(
                default_keychain_uid,
                sub_symkey_bytes,
                key_cipher_layers,
                0,
                cryptainer_metadata
        );
        if (!strcpy(sub_symkey_ciphertext, key_cipher_layers->u.key_ciphertext)){
            printf("Failed!");
            exit(EXIT_FAILURE);
        }
        wa_encrypt_bytestring(key_bytes, key_cipher_algo, sub_symkey, key_cipherdict);

    } else {
        if(!is_supported_algorithm(key_cipher_algo, SUPPORTED_ASYMMETRIC_KEY_ALGOS,supported_sym_key_count) ||
            !is_supported_algorithm(key_cipher_algo, SUPPORTED_CIPHER_ALGOS, supported_sym_key_count)) 
        {
            printf("%s is not a SIGNATURE algo", &key_cipher_algo);
            exit(EXIT_FAILURE);
        }
        if(!is_supported_algorithm(key_cipher_algo, SUPPORTED_ASYMMETRIC_KEY_ALGOS,supported_sym_key_count)) {
            printf("%s is not a SIGNATURE algo", &key_cipher_algo);
            exit(EXIT_FAILURE);
        }
        char keychain_uid[MAX_UID_LENGTH];
        char trustee[MAX_TRUSTEE_LENGTH];
        
        if(!strcpy(key_cipher_layers->u.keychain_uid, keychain_uid))
            strcpy(keychain_uid, default_keychain_uid);
        strcpy(key_cipher_layers->u.key_cipher_trustee, trustee);
        if (!wa_encrypt_key_with_asymmetric_cipher(key_cipher_algo, keychain_uid, key_bytes, trustee, cryptainer_metadata, key_cipherdict))
            exit(EXIT_FAILURE);
    }
    
    }

void wa_deepcopy_dict(const struct Cryptainer* source, struct Cryptainer* destination) {
    strcpy(destination->cryptainer_state, source->cryptainer_state);
    strcpy(destination->cryptainer_format, source->cryptainer_format);
    strcpy(destination->cryptainer_uid, source->cryptainer_uid);
    strcpy(destination->keychain_uid, source->keychain_uid);
    destination->payload_ciphertext_struct = NULL; // Assuming pointer is initialized to NULL
    destination->cryptainer_metadata = source->cryptainer_metadata; // Shallow copy for simplicity
}

Shard* wa_split_secret_into_shards(const uint8_t* secret, size_t secret_len, int shard_count, int threshold_count, int* full_shards_count) {
    if (shard_count <= 0) {
        fprintf(stderr, "Shards count must be strictly positive\n");
        exit(EXIT_FAILURE);
    }

    if (threshold_count > shard_count) {
        fprintf(stderr, "Threshold count can't be higher than shard count\n");
        exit(EXIT_FAILURE);
    }

    uint8_t** chunks;
    size_t num_chunks;
    split_as_chunks(secret, secret_len, &chunks, &num_chunks);

    uint8_t*** all_chunk_shards = (uint8_t***)malloc(num_chunks * sizeof(uint8_t**));
    for (size_t i = 0; i < num_chunks; ++i) {
        _split_128b_bytestring_into_shards(chunks[i], SHAMIR_CHUNK_LENGTH, shard_count, threshold_count, &all_chunk_shards[i]);
        free(chunks[i]);
    }
    free(chunks);

    Shard* full_shards = (Shard*)malloc(shard_count * sizeof(Shard));
    for (int i = 0; i < shard_count; ++i) {
        size_t shard_size = num_chunks * SHAMIR_CHUNK_LENGTH;
        full_shards[i].index = i + 1;
        full_shards[i].data = (uint8_t*)malloc(shard_size);

        for (size_t j = 0; j < num_chunks; ++j) {
            if (all_chunk_shards[j][i][0] != i + 1) {
                fprintf(stderr, "Shard index mismatch\n");
                exit(EXIT_FAILURE);
            }
            memcpy(full_shards[i].data + j * SHAMIR_CHUNK_LENGTH, all_chunk_shards[j][i] + 1, SHAMIR_CHUNK_LENGTH);
            free(all_chunk_shards[j][i]);
        }
        free(all_chunk_shards[i]);
    }
    free(all_chunk_shards);

    *full_shards_count = shard_count;
    return full_shards;
}

void wa_dump_to_json_bytes(unsigned char* key_cipherdict, unsigned char* key_bytes) {
    // Placeholder for the JSON serialization function
    // Replace this with actual implementation
    strcpy((char*)key_bytes, (char*)key_cipherdict);  
}

int wa_encrypt_bytestring(char* key_bytes, char* key_cipher_algo, char* sub_symkey[], Ciphertext* key_cipherdict) {
    return 0;
}
int wa_encrypt_key_with_asymmetric_cipher(
                                    char* cipher_algo, 
                                    char* keychain_uid, 
                                    char* key_bytes, 
                                    char** trustee,
                                    char** cryptainer_metadata,
                                    Ciphertext* key_cipherdict) 
{
    return 0;
}
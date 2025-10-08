#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SECRET_FILE "secrets.dat"
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define PBKDF2_ITER 100000
#define MAX_SECRET_SIZE 1024
#define MAX_PAIR_LINE 2048

void handle_errors(const char *msg){
    fprintf(stderr, "Error %s\n", msg);
    exit(1);
}

void derive_key(const char *password, unsigned char *salt, unsigned char *key){
    if(!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key)){
        handle_errors("Key derivation failed");
    }
}

int encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, int input_len, unsigned char **output){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) handle_errors("Creating context");

    int out_len = input_len + IV_SIZE;
    *output = malloc(out_len);
    if(!*output) handle_errors("Encrypt malloc");

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_errors("Init encrypt");

    int len, total = 0;
    if(!EVP_EncryptUpdate(ctx, *output, &len, input, input_len)) handle_errors("Encrypt update");
    total += len;
    if(!EVP_EncryptFinal_ex(ctx, *output + total, &len)) handle_errors("Encrypt final");
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

int decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, int input_len, unsigned char **output){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) handle_errors("Creating context");

    *output = malloc(input_len);
    if(!*output) handle_errors("Decrypt malloc");

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_errors("Init decrypt");

    int len, total = 0;
    if(!EVP_DecryptUpdate(ctx, *output, &len, input, input_len)) handle_errors("Decrypt update");
    total += len;
    if(!EVP_DecryptFinal_ex(ctx, *output + total, &len)) handle_errors("Decrypt final");
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

char *read_and_decrypt_file(const char *password, int *out_len){
    FILE *f = fopen(SECRET_FILE, "rb");
    if(!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if(sz < SALT_SIZE + IV_SIZE){
        fclose(f);
        return NULL;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    fread(salt, 1, SALT_SIZE, f);
    fread(iv, 1, IV_SIZE, f);

    int enc_len = sz - SALT_SIZE - IV_SIZE;
    unsigned char *enc_data = malloc(enc_len);
    fread(enc_data, 1, enc_len, f);
    fclose(f);

    unsigned char key[KEY_SIZE];
    derive_key(password, salt, key);

    unsigned char *decrypted = NULL;
    *out_len = decrypt(key, iv, enc_data, enc_len, &decrypted);
    free(enc_data);
    return (char *)decrypted;
}

void encrypt_and_write_file(const char *password, const char *plaintext, int plaintext_len){
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char *encrypted = NULL;

    if(!RAND_bytes(salt, sizeof(salt))) handle_errors("Salt gen");
    if(!RAND_bytes(iv, sizeof(iv))) handle_errors("IV gen");

    derive_key(password, salt, key);

    int enc_len = encrypt(key, iv, (const unsigned char *)plaintext, plaintext_len, &encrypted);

    FILE *f = fopen(SECRET_FILE, "wb");
    if(!f) handle_errors("Opening secret file for writing");
    fwrite(salt, 1, SALT_SIZE, f);
    fwrite(iv, 1, IV_SIZE, f);
    fwrite(encrypted, 1, enc_len, f);
    fclose(f);
    free(encrypted);
}

void store_secret(const char *password, const char *name, const char *value){
    int len = 0;
    char *plaintext = read_and_decrypt_file(password, &len);

    char buffer[MAX_SECRET_SIZE * 10] = {0};
    if(plaintext){
        strncpy(buffer, plaintext, len);
        free(plaintext);
    }

    char *line = strtok(buffer, "\n");
    char new_data[MAX_SECRET_SIZE * 10] = {0};
    int found = 0;

    while(line){
        if(strncmp(line, name, strlen(name)) == 0 && line[strlen(name)] == '='){
            found = 1;
            snprintf(new_data + strlen(new_data), sizeof(new_data) - strlen(new_data), "%s=%s\n", name, value);
        } else {
            snprintf(new_data + strlen(new_data), sizeof(new_data) - strlen(new_data), "%s\n", line);
        }
        line = strtok(NULL, "\n");
    }

    if(!found){
        snprintf(new_data + strlen(new_data), sizeof(new_data) - strlen(new_data), "%s=%s\n", name, value);
    }

    encrypt_and_write_file(password, new_data, strlen(new_data));
    printf("Secret stored.\n");
}

void get_secret(const char *password, const char *name){
    int len = 0;
    char *plaintext = read_and_decrypt_file(password, &len);
    if(!plaintext){
        printf("No secrets found.\n");
        return;
    }

    char *line = strtok(plaintext, "\n");
    while(line){
        if(strncmp(line, name, strlen(name)) == 0 && line[strlen(name)] == '='){
            printf("Secret: %s\n", line + strlen(name) + 1);
            free(plaintext);
            return;
        }
        line = strtok(NULL, "\n");
    }

    printf("Secret not found.\n");
    free(plaintext);
}

int main(int argc, char **argv){
    char password[256];
    char command[100];
    char name[256];
    char value[1024];

    printf("Enter your master password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    while(1){
        printf("Enter command (store/get/exit): ");
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = '\0';

        if(strcmp(command, "store") == 0){
            printf("Enter secret name: ");
            fgets(name, sizeof(name), stdin);
            name[strcspn(name, "\n")] = '\0';

            printf("Enter secret value: ");
            fgets(value, sizeof(value), stdin);
            value[strcspn(value, "\n")] = '\0';

            store_secret(password, name, value);
        }
        else if(strcmp(command, "get") == 0){
            printf("Enter secret name: ");
            fgets(name, sizeof(name), stdin);
            name[strcspn(name, "\n")] = '\0';

            get_secret(password, name);
        }
        else if(strcmp(command, "exit") == 0){
            break;
        }
        else{
            printf("Unknown command.\n");
        }
    }

    return 0;
}

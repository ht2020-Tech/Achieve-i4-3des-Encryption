#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/des.h>

//  Base64 
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//  Base64 
char* base64_encode_custom(const unsigned char *input, int length) {
    int output_length = ((length + 2) / 3) * 4;
    char *output = malloc(output_length + 1);
    int i, j;
    
    for (i = 0, j = 0; i < length; i += 3, j += 4) {
        unsigned int octet_a = i < length ? input[i] : 0;
        unsigned int octet_b = i + 1 < length ? input[i + 1] : 0;
        unsigned int octet_c = i + 2 < length ? input[i + 2] : 0;
        
        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        output[j] = base64_table[(triple >> 18) & 0x3F];
        output[j + 1] = base64_table[(triple >> 12) & 0x3F];
        output[j + 2] = i + 1 < length ? base64_table[(triple >> 6) & 0x3F] : '=';
        output[j + 3] = i + 2 < length ? base64_table[triple & 0x3F] : '=';
    }
    
    output[output_length] = '\0';
    return output;
}

// Get time
long long get_current_timestamp_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// PKCS7
int pkcs7_padding(unsigned char *data, int data_len, int block_size) {
    int padding = block_size - (data_len % block_size);
    for (int i = 0; i < padding; i++) {
        data[data_len + i] = (unsigned char)padding;
    }
    return data_len + padding;
}

// 3DES
unsigned char* encrypt_3des(const unsigned char *data, int data_len, 
                            const unsigned char *key, int *out_len) {
    const EVP_CIPHER *cipher = EVP_des_ede3_ecb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx) {
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    unsigned char *outbuf = (unsigned char*)malloc(data_len + EVP_CIPHER_block_size(cipher));
    int outlen = 0, tmplen = 0;
    
    if (EVP_EncryptUpdate(ctx, outbuf, &outlen, data, data_len) != 1) {
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen) != 1) {
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    *out_len = outlen;
    return outbuf;
}

// URL
char* url_encode(const char *str) {
    int len = strlen(str);
    char *encoded = malloc(len * 3 + 1);
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        unsigned char c = str[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded[pos++] = c;
        } else {
            pos += sprintf(encoded + pos, "%%%02X", c);
        }
    }
    encoded[pos] = '\0';
    return encoded;
}

// Make JSON
char* build_json(long long ecid, const char *model, long long timestamp) {
    char *json = malloc(256);
    snprintf(json, 256, "{\"ecid\":%lld,\"model\":\"%s\",\"time\":%lld}", 
             ecid, model, timestamp);
    return json;
}

int main(int argc, char *argv[]) {
    long long ecid = 0;
    char *model = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ecid") == 0 && i + 1 < argc) {
            ecid = atoll(argv[++i]);
        } else if (strcmp(argv[i], "-model") == 0 && i + 1 < argc) {
            model = argv[++i];
        }
    }
    
    if (ecid == 0 || model == NULL) {
        fprintf(stderr, "Usage: %s -ecid <ecid> -model <model>\n", argv[0]);
        return 1;
    }
    
    long long timestamp = get_current_timestamp_ms();
    char *json_data = build_json(ecid, model, timestamp);
    
    const char *key_str = "2015aisi1234sj7890smartflashi4pc";
    unsigned char key[24];
    int key_len = strlen(key_str);
    for (int i = 0; i < 24; i++) {
        key[i] = (unsigned char)key_str[i % key_len];
    }
    
    int json_len = strlen(json_data);
    unsigned char *padded_data = (unsigned char*)malloc(json_len + 8);
    memcpy(padded_data, json_data, json_len);
    int padded_len = pkcs7_padding(padded_data, json_len, 8);
    
    int encrypted_len;
    unsigned char *encrypted = encrypt_3des(padded_data, padded_len, key, &encrypted_len);
    
    if (!encrypted) {
        fprintf(stderr, "Encryption failed\n");
        free(json_data);
        free(padded_data);
        return 1;
    }
    
    char *base64_str = base64_encode_custom(encrypted, encrypted_len);
    char *urlencoded = url_encode(base64_str);
    
    printf("%s\n", urlencoded);
    
    free(json_data);
    free(padded_data);
    free(encrypted);
    free(base64_str);
    free(urlencoded);
    
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    // 初始化 OpenSSL 库
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 生成 RSA 密钥对
    RSA *rsa = RSA_generate_key(2048, 65537, NULL, NULL);
    if (!rsa) {
        printf("RSA key generation failed");
    }

    // 提取公钥信息
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);

    char *modulus = BN_bn2hex(n); // 公钥模数 (n)
    char *exponent = BN_bn2hex(e); // 公钥指数 (e)

    printf("Public Key:\n");
    printf("Modulus (n): %s\n", modulus);
    printf("Modulus Length: %zu bytes\n", BN_num_bytes(n));
    printf("Exponent (e): %s\n", exponent);
    printf("Exponent Length: %zu bytes\n\n", BN_num_bytes(e));

    // 读取文件内容
    FILE *file = fopen("input.txt", "rb");
    if (!file) {
        printf("Unable to open input.txt");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for file data");
    }
    fread(file_data, 1, file_size, file);
    fclose(file);

    // 对文件内容进行签名
    unsigned char *signature = malloc(RSA_size(rsa));
    unsigned int signature_length;

    if (RSA_sign(NID_sha256, file_data, file_size, signature, &signature_length, rsa) != 1) {
        printf("RSA signing failed");
    }

    printf("Signature:\n");
    for (unsigned int i = 0; i < signature_length; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    printf("Signature Length: %u bytes\n", signature_length);

    // 清理资源
    free(file_data);
    free(signature);
    free(modulus);
    free(exponent);
    RSA_free(rsa);

    // 清理 OpenSSL 库
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
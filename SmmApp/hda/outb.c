#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/io.h>
#include <unistd.h>

// RSA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// must be the same with smm driver
#define KEYLEN 2048
#define RSA_N_LEN 256
#define RSA_E_LEN 3

#define MAX_FILE_LEN 1024
#define MAX_SIGNATURE_LEN 256

struct SignedFile {
    unsigned char signature[MAX_SIGNATURE_LEN];
    size_t signatureLen;
    unsigned char data[MAX_FILE_LEN];
    size_t dataLen;
};

struct PublicKey {
    unsigned char N[RSA_N_LEN];
    size_t NLen;
    unsigned char E[RSA_E_LEN];
    size_t ELen;
};


#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

uint64_t virt_to_phys(void *virt_addr) {
    int fd;
    uint64_t virt_pfn;
    uint64_t phys_pfn;
    uint64_t offset = (uint64_t)virt_addr % PAGE_SIZE;
    uint64_t entry;
    ssize_t bytes_read;

    // Open the pagemap file for the current process
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    // Calculate the page frame number for the virtual address
    virt_pfn = (uint64_t)virt_addr >> PAGE_SHIFT;

    // Seek to the entry in pagemap
    if (lseek(fd, virt_pfn * sizeof(entry), SEEK_SET) == (off_t)-1) {
        perror("lseek");
        close(fd);
        return 0;
    }

    // Read the entry from pagemap
    bytes_read = read(fd, &entry, sizeof(entry));
    if (bytes_read != sizeof(entry)) {
        perror("read");
        close(fd);
        return 0;
    }

    // Check if the page is present
    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        close(fd);
        return 0;
    }

    // Extract the physical frame number
    phys_pfn = entry & ((1ULL << 55) - 1);

    // Calculate the physical address
    uint64_t phys_addr = (phys_pfn << PAGE_SHIFT) | offset;

    close(fd);
    return phys_addr;
}

#define PORT 0xb2
#define SMM_APP 0x05

#define SMM_APP_MMI_SERVICE 0x01
#define SMM_APP_MMI_UPDATE 0x02

void smm_call(uint64_t mmi_id, uint64_t arg0, uint64_t arg1) {
    asm volatile("mov %0, %%rdi\n\t"
                 "mov %1, %%rsi\n\t"
                 "mov %2, %%r10\n\t"
                 "outb %b3, %w4"
                 :
                 : "r"(mmi_id), "r"(arg0), "r"(arg1), "a"(SMM_APP), "Nd"(PORT)
                 : "rdi", "rsi", "r10", "memory");
}

void smm_service() {
    // TODO: fake service
    smm_call(SMM_APP_MMI_SERVICE, 0, 0);
}

void smm_update(void *addr, size_t len) {
    // update here
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
    char n_len = BN_num_bytes(n);
    char e_len = BN_num_bytes(e);

    printf("Public Key:\n");
    printf("Modulus (n): %s\n", modulus);
    printf("Modulus Length: %zu bytes\n", n_len);
    printf("Exponent (e): %s\n", exponent);
    printf("Exponent Length: %zu bytes\n\n", e_len);

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

    struct SignedFile signed_file = {
        .signature = signature,
        .signatureLen = (size_t)signature_length,
        .data = file_data,
        .dataLen = (size_t)file_size
    };
    struct PublicKey public_key = {
        .N = modulus,
        .NLen = n_len,
        .E = exponent,
        .ELen = e_len
    };




    // uint64_t pa = virt_to_phys(addr);
    // smm_call(SMM_APP_MMI_UPDATE, pa, len);
    uint64_t pa = virt_to_phys(&signed_file);
    uint64_t pb = virt_to_phys(&public_key);
    smm_call(SMM_APP_MMI_UPDATE, pa, pb);

    // 清理 OpenSSL 库
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // 清理资源
    free(file_data);
    free(signature);
    free(modulus);
    free(exponent);
    RSA_free(rsa);

}

int main() {
    // 请求访问 0xb2 端口
    if (ioperm(PORT, 1, 1)) {
        perror("ioperm");
        return 1;
    }

    // 向 0xb2 端口写入 0x05
    // outb(0x05, 0xb2);

    size_t val = 10;
    size_t len = 1;
    smm_update(&val, len);
    smm_service();

    // 释放 0xb2 端口的访问权限
    if (ioperm(PORT, 1, 0)) {
        perror("ioperm");
        return 1;
    }

    return 0;
}

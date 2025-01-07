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
#define RSA_N_LEN 1024
#define RSA_E_LEN 10

#define MAX_FILE_LEN 1024
#define MAX_SIGNATURE_LEN 256

struct SignedFile {
    unsigned char signature[MAX_SIGNATURE_LEN];
    size_t signatureLen;
    unsigned char data[MAX_FILE_LEN];
    size_t dataLen;
} __attribute__((aligned(4096)));

struct PublicKey {
    unsigned char N[RSA_N_LEN];
    size_t NLen;
    unsigned char E[RSA_E_LEN];
    size_t ELen;
} __attribute__((aligned(4096)));

// DEBUG print buffer
void print_buffer(const unsigned char *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}


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

void smm_update(char *filename, int modify_file) {
    // update here

    printf("-----------------Vendor Starting Sign their new firmware------------\n");
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

    unsigned char *n_buffer = malloc(RSA_N_LEN);
    unsigned char *e_buffer = malloc(RSA_E_LEN);

    size_t n_len = BN_bn2bin(n, n_buffer);
    size_t e_len = BN_bn2bin(e, e_buffer);

    // printf("Public Key:\n");
    // print_buffer(n_buffer, n_len);
    // printf("bin Modulus Length: %zu bytes\n", n_len);
    // print_buffer(e_buffer, e_len);
    // printf("bin Exponent Length: %zu bytes\n\n", e_len);

    // 读取文件内容
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Unable to open input.txt");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_data; //  = malloc(file_size);
    posix_memalign(&file_data, 4096, file_size);
    if (!file_data) {
        printf("Memory allocation failed for file data");
    }
    fread(file_data, 1, file_size, file);
    fclose(file);

    printf("File Data:\n");
    print_buffer(file_data, file_size);
    printf("File Data Length: %ld bytes\n\n", file_size);
    // 对文件内容进行签名
    unsigned char *signature = malloc(RSA_size(rsa));
    unsigned int signature_length;

    if (RSA_sign(NID_sha256, file_data, file_size, signature, &signature_length, rsa) != 1) {
        printf("RSA signing failed");
        ERR_print_errors_fp(stderr);
    }

    printf("Signature:\n");
    print_buffer(signature, signature_length);
    // modified signature
    // signature[0] = 'a';

    printf("\n");
    printf("Signature Length: %u bytes\n", signature_length);

    printf("-----------------Vendor Finished Sign their new firmware------------\n");
    
    if (modify_file) {
        printf("-----------------Hacker hack the firmware--------------\n");
        file_data[0] = file_data[0] + 1;
        printf("File Data:\n");
        print_buffer(file_data, file_size);
    }

    printf("---------------SMM driver start to verify&update the firmware------------\n");

    struct SignedFile signed_file;
    memcpy(signed_file.signature, signature, signature_length);
    signed_file.signatureLen = signature_length;
    memcpy(signed_file.data, file_data, file_size);
    signed_file.dataLen = file_size;
    struct PublicKey public_key;
    memcpy(public_key.N, n_buffer, n_len);
    public_key.NLen = n_len;
    memcpy(public_key.E, e_buffer, e_len);
    public_key.ELen = e_len;

    uint64_t pa = virt_to_phys(&signed_file);
    uint64_t pb = virt_to_phys(&public_key);
    smm_call(SMM_APP_MMI_UPDATE, pa, pb);

    printf("---------------SMM driver finished to verify&update the firmware------------\n");



    // 清理 OpenSSL 库
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    // 清理资源
    free(file_data);
    free(signature);
    // free(modulus);
    // free(exponent);
    free(n_buffer);
    free(e_buffer);
    RSA_free(rsa);
}

int main( int argc, char *argv[] ) {
    char filename[100];
    int modify_file = 0;
    if (argc < 2) {
        printf("Usage: %s <filename> <is_modify_file>\n", argv[0]);
        return 1;
    }
    strcpy(filename, argv[1]);
    if (argc == 3) {
        modify_file = 1;
    }

    // 请求访问 0xb2 端口
    if (ioperm(PORT, 1, 1)) {
        perror("ioperm");
        return 1;
    }

    // 向 0xb2 端口写入 0x05
    // outb(0x05, 0xb2);

    printf("-------------call firmware service---------\n");
    smm_service();

    smm_update(filename, modify_file);
    printf("-------------call firmware service---------\n");
    smm_service();

    // 释放 0xb2 端口的访问权限
    if (ioperm(PORT, 1, 0)) {
        perror("ioperm");
        return 1;
    }

    return 0;
}

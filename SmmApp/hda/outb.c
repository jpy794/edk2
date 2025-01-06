#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/io.h>
#include <unistd.h>

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
    uint64_t pa = virt_to_phys(addr);
    smm_call(SMM_APP_MMI_UPDATE, pa, len);
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

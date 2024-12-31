#include <stdio.h>
#include <sys/io.h>

int main() {
    // 请求访问 0xb2 端口
    if (ioperm(0xb2, 1, 1)) {
        perror("ioperm");
        return 1;
    }

    // 向 0xb2 端口写入 5
    // debug.log 输出: SmmAppMmi(): smi
    outb(0x05, 0xb2);

    // 释放 0xb2 端口的访问权限
    if (ioperm(0xb2, 1, 0)) {
        perror("ioperm");
        return 1;
    }

    return 0;
}


#define _POSIX_C_SOURCE 199309L
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "sm4.h"
void sm4_speed()
{
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char input[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char output[16];
    sm4_context ctx;
    long max_num = 1024*1024;
    long i=0;
    sm4_setkey_enc(&ctx, key);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    // 进行加密
    for (; i < max_num; i++){
        sm4_crypt_ecb(&ctx, 1, 16, input, input);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    // 计算时间
    double time_spent = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    // 计算吞吐量
    double throughput = 16*(max_num/(1024*1024)) / time_spent; 
    printf("SM4 throughput: %f MiB/s\n", throughput);
}
void sm4_correctness()
{
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char cipher[16];
    int i;
    sm4_context ctx;
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 1, 16, plain, cipher);
    printf("SM4 correctness test:\n");
    // 输出明文
    printf("Plaintext:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", plain[i]);
    // 输出密文
    printf("\nCiphertext:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", cipher[i]);
    // 解密
    sm4_setkey_dec(&ctx, key);
    unsigned char plain2[16];
    sm4_crypt_ecb(&ctx, 0, 16, cipher, plain2);
    printf("\nDecrypted:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", plain2[i]);
    printf("\n");
    // 检查解密结果是否与原始明文相同
    if (memcmp(plain, plain2, 16) == 0)
        printf("Decryption successful!\n");
    else
        printf("Decryption failed!\n"); 
}
int main(int argc, char** argv)
{
    sm4_correctness();
    sm4_speed();
	return 0;
}
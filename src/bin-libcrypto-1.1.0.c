#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main()
{
unsigned char ibuf[] = "Hello, World";
unsigned char obuf[20];

printf("lscan binary test file statically linked with libcrypto-1.1.0\n");


SHA1(ibuf, strlen(ibuf), obuf);

int i;
for (i = 0; i < 20; i++) {
printf("%02x", obuf[i]);
}
printf("\n");

return 0;

}

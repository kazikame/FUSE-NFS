#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#define WRITE_SIZE 1024 * 1024 * 1024
#define CHUNK_SIZE 1024 * 1024
int main() {
   int fd0 = open("tmp.file", O_RDWR | O_CREAT | O_TRUNC);
   char buf[CHUNK_SIZE];
   buf[0] = 9;
   buf[1] = 81;
   buf[2] = 'A';
   buf[3] = 'q';
   buf[4] = '0';

   int num_written = 0;

   while (num_written < WRITE_SIZE) {
       num_written += write(fd0, buf, sizeof(buf));
    //    printf("Wrote %d bytes\n", num_written);
   }
   close(fd0);
   printf("Wrote %d bytes\n", num_written);
   return 0;
}
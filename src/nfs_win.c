#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

int main() {
   int fd0 = open("newfile", O_RDWR | O_APPEND);
   char buf[100];
   buf[0] = 9;
   buf[1] = 81;
   buf[2] = 'A';
   buf[3] = 'q';
   buf[4] = '0';
   int nb0 = write(fd0, buf, 100);
   close(fd0);
   printf("Wrote %d bytes\n", nb0);
   return 0;
}
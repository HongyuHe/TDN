#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
__attribute__((constructor)) static void check(void){int fd=open("/etc/swanctl/private/key.pem",O_RDONLY);printf("owned-test-key-open=%s\n",fd>=0?"opened":"denied");if(fd>=0)close(fd);}

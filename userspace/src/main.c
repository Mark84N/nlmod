#include <stdio.h>
#include <unistd.h>

#include "gnl_app.h"

int main(int argc, char **argv)
{
    int gnl_sock;
    int gnl_fam;

    if ((gnl_sock = create_gnl_sock()) < 0) {
        perror("error");
        return -1;
    }

    if ((gnl_fam = get_gnl_fam(gnl_sock)) < 0) {
        perror("error");
        close(gnl_sock);
        return -1;
    }

    printf("Success: %d\n", gnl_fam);

    return 0;
}
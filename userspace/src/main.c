#include <stdio.h>
#include <unistd.h>

#include "gnl_app.h"

int main(int argc, char **argv)
{
    int gnl_sock = -1, gnl_fam = -1;
    int ret = 1;

    if ((gnl_sock = gnl_create_sock()) < 0)
        goto out;

    if ((gnl_fam = gnl_get_fam(gnl_sock)) < 0)
        goto out;

    printf("Success: family#%d\n", gnl_fam);

    if (gnl_test_cmd(gnl_sock) < 0)
        goto out;

    ret = 0;
out:
    if (ret != 0)
        perror("error");
    if (gnl_sock != -1)
        close(gnl_sock);

    return ret;
}

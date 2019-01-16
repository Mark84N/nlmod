#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include "nlmod_common.h"
#include "gnl_app.h"

static struct common {
    unsigned long seq;
} common = { .seq = 1, };

void hexdump(const unsigned char *data, size_t size)
{
    const static int max_bytes_per_line = 16;
    int i = 0;

    printf("------- start dump, len=%lu -------\n", size);
    while (i < size) {
        int cur_line = max_bytes_per_line;
        int hex = i, ascii = hex;

        for (; i < size && cur_line > 0; i++, cur_line--) {
            printf("%.2X ", data[hex++]);
            /* additional spacing between bytes in a line */
            if ((cur_line - 1) == max_bytes_per_line / 2)
                printf("  ");
        }
        /* spacing between bytes possibly haven't been printed' */
        if (cur_line > 9)
            printf("  ");

        /* missing bytes in hex line */
        while (cur_line-- > 0)
            printf("   ");
        printf("| ");

        for (; ascii != hex; ascii++)
            printf("%c ", isprint(data[ascii])? data[ascii] : '.');
        printf("\n");
    }
    //printf("------- end dump -------\n");
}

int get_gnl_fam(int gnl_sock)
{
    struct sockaddr_nl nl_addr;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct nl_msg *nlmsg;
    int gnl_fam = -1;
    int total_len = 0;
    int nla_data_len;
    int ret;
    int remain;

    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    total_len = NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN);

    nlhdr = &nlmsg->nlhdr;
    nlhdr->nlmsg_type = GENL_ID_CTRL;
    nlhdr->nlmsg_seq = common.seq++;
    nlhdr->nlmsg_flags = NLM_F_REQUEST;
    nlhdr->nlmsg_pid = getpid();
    nlmsg->gnlhdr.cmd = CTRL_CMD_GETFAMILY;

    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla_data_len =  strlen(NLMOD_CUSTOM_NAME) + 1;
    nla->nla_len = NLA_HDRLEN + nla_data_len;
    /* copy nla payload */
    strncpy(((char *)nla + NLA_HDRLEN), NLMOD_CUSTOM_NAME, 
                sizeof(struct nl_msg) - (total_len + NLA_HDRLEN));

    total_len += NLMSG_ALIGN(NLA_HDRLEN + nla_data_len);
    nlhdr->nlmsg_len = total_len;

    memset(&nl_addr, 0, sizeof(struct sockaddr_nl));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = 0;

    iov.iov_base = nlmsg;
    iov.iov_len = total_len;

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = &nl_addr;
    msg.msg_namelen = sizeof(nl_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    hexdump((unsigned char *)nlmsg, total_len);

    /*send*/
    while ((ret = sendmsg(gnl_sock, &msg, 0)) == -1) {
        static int retry = 0;
        printf("error: %d, try#%d\n", errno, retry);
        usleep(50000); // 50 ms
        if (retry++ >= 5)
            goto failure;
    }

    printf("Sent %d bytes!, family requested: \"%s\"\n", ret, NLMOD_CUSTOM_NAME);

    /*receive*/
    memset(nlmsg, 0, sizeof(struct nl_msg));
    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto failure;

    printf("Received %d bytes!\n", ret);
    hexdump((unsigned char *)nlmsg, ret);

    if (nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr, ret))
        goto failure;
    /*
    *  Received msg layout:
    *  +------------------------------------------------------------------+
    *  | NLMSGHDR | PAD | GENLMSGHDR | PAD | NLA_HDR | NLA_DATA | PAD | ...
    *  +------------------------------------------------------------------+
    */

    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);
    nla_for_each_attr(nla, genlmsg_data_len(nlhdr), remain) {
        static int count = 1;
        printf("Attribute #%d\n", count++);
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            gnl_fam = *(uint16_t *)((char *)nla + NLA_HDRLEN);
            printf("Family: %hu\n", gnl_fam);
        }
    }

failure:
    if (nlmsg)
        free(nlmsg);
    return gnl_fam;
}

int create_gnl_sock(void)
{
    int sockd;
    struct sockaddr_nl nl_addr;

    if ((sockd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) < 0)
        return -1;

    memset(&nl_addr, 0, sizeof(struct sockaddr_nl));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = getpid();

    if (bind(sockd, (struct sockaddr *)&nl_addr, sizeof(struct sockaddr_nl)) < 0)
        goto failure;

    return sockd;

failure:
    if (sockd != -1)
        close(sockd);
    return -1;
}

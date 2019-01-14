#include <stdio.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "nlmod_common.h"

static struct common {
    unsigned long seq;
} common;

#define GENLMSG_DATA(msg) \
        ((char *)(msg) + NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN))
#define NLA_NEXT(nla) \
        (struct nlattr *)((char *)(nla) + NLA_ALIGN(nla->nla_len))
#define NLA_DATA(nla) \
        ((char *)(nla) + NLA_HDRLEN)
#define NLA_PRESENT(nlmsg) 1

#define NLMSG_FOR_EACH_ATTR(nlmsg) 1

struct nl_msg {
    struct nlmsghdr nlhdr;
    struct genlmsghdr gnlhdr;
    uint8_t payload[2048];
};

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
    printf("------- end dump -------\n");
}

int get_gnl_fam(int gnl_sock)
{
    struct sockaddr_nl nl_addr;
    struct nl_msg *nlmsg;
    struct nlmsghdr *nlhdr;
    struct genlmsghdr *gnlhdr;
    struct nlattr *nla;
    struct iovec iov;
    struct msghdr msg;
    int gnl_fam = -1;
    int total_len = 0;
    int nla_data_len;
    int ret;

    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    /* | NL HEADER | GENL HEADER | <payload>
        <-------total_len------->    
    */
    total_len = NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN);

    nlmsg->nlhdr.nlmsg_type = GENL_ID_CTRL;
    nlmsg->nlhdr.nlmsg_seq = common.seq++;
    nlmsg->nlhdr.nlmsg_flags = NLM_F_REQUEST;
    nlmsg->nlhdr.nlmsg_pid = getpid();
    nlmsg->gnlhdr.cmd = CTRL_CMD_GETFAMILY;

    gnlhdr = (struct genlmsghdr *)NLMSG_DATA(nlmsg);
    nla = (struct nlattr *)((char *)gnlhdr + GENL_HDRLEN);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla_data_len =  strlen(NLMOD_CUSTOM_NAME) + 1;
    nla->nla_len = NLA_HDRLEN + nla_data_len;
    /* copy nla payload */
    strncpy(((char *)nla + NLA_HDRLEN), NLMOD_CUSTOM_NAME, 
                sizeof(struct nl_msg) - (total_len + NLA_HDRLEN));

    total_len += NLMSG_ALIGN(NLA_HDRLEN + nla_data_len);
    nlmsg->nlhdr.nlmsg_len = total_len;

    memset(&nl_addr, 0, sizeof(struct sockaddr_nl));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = 0;

    iov.iov_base = nlmsg;
    iov.iov_len = total_len;

    msg.msg_name = &nl_addr;
    msg.msg_namelen = sizeof(nl_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    hexdump(nlmsg, total_len);

    /*send*/
    if ((ret = sendmsg(gnl_sock, &msg, 0)) == -1) {
        printf("error: %d\n", errno);
        goto failure;
    }

    printf("Sent %d bytes!, family requested: \"%s\"\n", ret, NLMOD_CUSTOM_NAME);

    /*receive*/
    memset(nlmsg, 0, sizeof(struct nl_msg));
    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto failure;

    printf("Received %d bytes!\n", ret);
    hexdump(nlmsg, ret);

    /*
    *  Received msg layout:
    *  +------------------------------------------------------------------+
    *  | NLMSGHDR | PAD | GENLMSGHDR | PAD | NLA_HDR | NLA_DATA | PAD | ...
    *  +------------------------------------------------------------------+
    */
    /*for (nla = GENLMSG_DATA(); nla && data_left; nla = NLA_NEXT(nla)) {

    }*/
    if (nlmsg->nlhdr.nlmsg_type == NLMSG_ERROR || (ret < 0) 
            || !NLMSG_OK(&(nlmsg->nlhdr), ret)) {
        printf("E R R O R\n");
        goto failure;
    }

    gnlhdr = (struct genlmsghdr *)NLMSG_DATA(nlmsg);
    nla = (struct nlattr *)((char *)gnlhdr + GENL_HDRLEN);

    /* here should be for loop for parsing attributes, to find family id */
    if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
        /* TODO: wrap nla-related data access into a macro */
        gnl_fam = *(uint16_t *)((char *)nla + NLA_HDRLEN);
        printf("Family: %hu\n", gnl_fam);
    }

    free(nlmsg);

    return gnl_fam;
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

int main(int argc, char **argv)
{
    int gnl_sock;
    int gnl_fam;
    
    common.seq = 1;

    if ((gnl_sock = create_gnl_sock()) < 0) {
        perror("error");
        return -1;
    }

    if ((gnl_fam = get_gnl_fam(gnl_sock)) < 0) {
        perror("error");
        return -1;
    }

    printf("Success: %d\n", gnl_fam);

    return 0;
}
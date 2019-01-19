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

static struct gnl_data {
    unsigned long seq;
} gnl_data = { .seq = 1, };

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
}

/*
    Attributes are kept in iov member of cfg
    to be appended then to the msg.
*/
struct gnl_attr {
  int type;
  int len;
  void *data;
};

/*
    An attempt of generalizing sending API.
    Probably ugly, yet functional.
*/
struct gnl_msg_cfg {
    int nlmsg_type;
    int nlmsg_flags;
    int gnl_cmd;
    /* a pointer to the array of iov, each of which holds gnl_attr */
    struct iovec *iov;
    /* qty of iov strutures pointed by iov * above */
    int iov_len;
};

static int gnl_send_msg(int gnl_sock, struct gnl_msg_cfg *cfg)
{
    struct sockaddr_nl nl_addr;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct nl_msg *nlmsg;
    int total_len = 0;
    int ret = 0;

    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    total_len = NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN);

    nlhdr = &nlmsg->nlhdr;
    nlhdr->nlmsg_type = cfg->nlmsg_type;
    nlhdr->nlmsg_seq = gnl_data.seq++;
    nlhdr->nlmsg_flags = cfg->nlmsg_flags;
    nlhdr->nlmsg_pid = getpid();
    nlmsg->gnlhdr.cmd = cfg->gnl_cmd;

    /* nla start */
    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);

    /* add the attributes from the config to the msg */
    for (int i = 0; i < cfg->iov_len; i++) {
        struct iovec *iov = cfg->iov;
        struct gnl_attr *gnl_attr = (struct gnl_attr *)iov->iov_base;
        int nla_data_len = gnl_attr->len;
        int nla_total_len =  NLMSG_ALIGN(NLA_HDRLEN + nla_data_len);
        int remain = sizeof(struct nl_msg) - total_len;

        if (remain < nla_total_len)
            break;

        total_len += nla_total_len;
        nla->nla_type = gnl_attr->type;
        nla->nla_len = NLA_HDRLEN + nla_data_len;
        /* copy nla payload */
        memcpy(((char *)nla + NLA_HDRLEN), gnl_attr->data, nla_data_len);

        printf("Debug: attr #%d in a loop - done\n", i);
        /* advance to the next attr */
        nla = (struct nlattr *)((char *)nla + nla_total_len);
        iov++;
    }

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
        usleep(250 * 1000); // 250 ms
        if (retry++ >= 5)
            goto failure;
    }

    printf("Sent %d bytes!, family requested: \"%s\"\n", ret, NLMOD_CUSTOM_NAME);

failure:
    if (nlmsg)
        free(nlmsg);

    return ret;
}

int gnl_get_fam(int gnl_sock)
{
    struct nl_msg *nlmsg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct iovec iov;
    struct gnl_attr gnl_attr;
    struct gnl_msg_cfg cfg = {
        .nlmsg_type = GENL_ID_CTRL,
        .nlmsg_flags = NLM_F_REQUEST,
        .gnl_cmd = CTRL_CMD_GETFAMILY,
        .iov = &iov,
        .iov_len = 1,
    };
    int gnl_fam = -1;
    int remain;
    int ret;

    gnl_attr.type = CTRL_ATTR_FAMILY_NAME;
    gnl_attr.len = strlen(NLMOD_CUSTOM_NAME) + 1;
    gnl_attr.data = NLMOD_CUSTOM_NAME;

    iov.iov_base = &gnl_attr;
    iov.iov_len = sizeof(struct gnl_attr);

    /* send */
    gnl_send_msg(gnl_sock, &cfg);

    /* prepare to receive */
    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto failure;

    printf("Received %d bytes!\n", ret);
    hexdump((unsigned char *)nlmsg, ret);

    nlhdr = &nlmsg->nlhdr;
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
            break;
        }
    }

failure:
    if (nlmsg)
        free(nlmsg);
    return gnl_fam;
}

int gnl_create_sock(void)
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

int gnl_test_cmd(int gnl_sock, int family)
{
    struct nl_msg *nlmsg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct iovec iov;
    struct gnl_attr gnl_attr;
    struct gnl_msg_cfg cfg = {
        .nlmsg_type = family,
        .nlmsg_flags = NLM_F_REQUEST,
        .gnl_cmd = NLMODULE_GET_STR,
        .iov = &iov,
        .iov_len = 1,
    };
    int ret = 0, remain = 0;
    const char *str;

    gnl_attr.type = CTRL_ATTR_FAMILY_NAME;
    gnl_attr.len = strlen(NLMOD_CUSTOM_NAME) + 1;
    gnl_attr.data = NLMOD_CUSTOM_NAME;

    iov.iov_base = &gnl_attr;
    iov.iov_len = sizeof(struct gnl_attr);

    /* send */
    gnl_send_msg(gnl_sock, &cfg);

    /* prepare to receive */
    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto failure;

    printf("Received %d bytes!\n", ret);
    hexdump((unsigned char *)nlmsg, ret);

    nlhdr = &nlmsg->nlhdr;
    if (nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr, ret))
        goto failure;

    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);
    nla_for_each_attr(nla, genlmsg_data_len(nlhdr), remain) {
        static int count = 1;
        printf("Attribute #%d\n", count++);
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            str = (const char *)((char *)nla + NLA_HDRLEN);
            printf("Received: %s\n", str);
            break;
        }
    }

failure:
    if (nlmsg)
        free(nlmsg);

    return ret;
}

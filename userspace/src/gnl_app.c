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
    @gnl_parse_attr() - Parse a stream of atrributes from the nlmsg to attrtbl.
    @nlh: Pointer to a nlmsghdr received.
    @attrtbl: Pointer to an array of pointers to nlattr with len=(sizeof(nlattr) * maxattr).

    Return: Number of attributes parsed or -1 on error.
*/
static int gnl_parse_attr(struct nlmsghdr *nlh, struct nlattr **attrtbl)
{
    struct nlattr *nla;
    int attrcount = 0, remain = 0;
    int ret = -1;

    /* should never happen */
    if (!nlh || !attrtbl)
        return -1;

    memset(attrtbl, 0, sizeof(struct nlattr *) * __NLMODULE_MAX);
    nla = (struct nlattr *)GENLMSG_DATA(nlh);

    nla_for_each_attr(nla, genlmsg_data_len(nlh), remain) {
        if (nla && nla_type_ok(nla)) {
            attrcount++;
            /* TODO: maybe some additional validation? */
            attrtbl[nla->nla_type] = nla;
        }
    }
    ret = attrcount;

    if (remain)
        printf("Error! Something left=%d after parsing attributes.\n", remain);
fail:
    return ret;
}

/*
    gnl_send_msg() - Based on a cfg, compose & send generic NL msg.
    @gnl_sock: Generic NL socket descriptor.
    @cfg: Pointer to a message config (see below).

    Return: 0 on success or errno.

    Description: struct gnl_msg_cfg is used to generalize the API of
    sending messages. It takes most common parameters:
    *nlmsg_type: type of message (i.e. family);
    *nlmsg_flags: message flags;
    *gnl_cmd: type of family-specific command;
    *gnlattr: pointer to an array of struct gnl_attr *;
    *attrcount: attributes in the aray;

    struct gnl_attr describes attributes in a TLV-manner.
*/
static int gnl_send_msg(int gnl_sock, struct gnl_msg_cfg *cfg)
{
    struct sockaddr_nl nl_addr;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct gnl_attr *gnl_attr;
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

    /* start location to write attributes */
    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);
    gnl_attr = cfg->gnlattr;

    /* append attributes to the nlmsg */
    for (int i = 0; i < cfg->attrcount && gnl_attr; i++) {
        int nla_data_len = gnl_attr->len;
        int nla_total_len =  NLMSG_ALIGN(NLA_HDRLEN + nla_data_len);
        int remain = sizeof(struct nl_msg) - total_len;

        if (remain < nla_total_len)
            break;

        total_len += nla_total_len;
        nla->nla_type = gnl_attr->type;
        nla->nla_len = NLA_HDRLEN + nla_data_len;
        /* copy nla payload */
        memcpy(nla_data(nla), gnl_attr->data, nla_data_len);

        printf("Debug: attr #%d - added %d bytes to a msg\n",
                    i, nla_total_len);
        /* move ptr to write the next attribute */
        nla = (struct nlattr *)((char *)nla + nla_total_len);
        gnl_attr++;
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

    while ((ret = sendmsg(gnl_sock, &msg, 0)) == -1) {
        static int retry = 0;
        usleep(250 * 1000); // 250 ms
        if (retry++ >= 5)
            goto fail;
    }

fail:
    if (nlmsg)
        free(nlmsg);

    return ret;
}

/*
    gnl_get_fam() - Get id of a custom NL family by the name.
    @gnl_sock: Generic NL socket descriptor.

    Return: Family id or -1 on error.
*/
int gnl_get_fam(int gnl_sock)
{
    struct nl_msg *nlmsg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct gnl_attr gnl_attr;
    struct gnl_msg_cfg cfg = {
        .nlmsg_type = GENL_ID_CTRL,
        .nlmsg_flags = NLM_F_REQUEST,
        .gnl_cmd = CTRL_CMD_GETFAMILY,
        .gnlattr = &gnl_attr,
        .attrcount = 1,
    };
    int gnl_fam = -1;
    int remain;
    int ret;

    gnl_attr.type = CTRL_ATTR_FAMILY_NAME;
    gnl_attr.len = strlen(NLMOD_CUSTOM_NAME) + 1;
    gnl_attr.data = NLMOD_CUSTOM_NAME;

    gnl_send_msg(gnl_sock, &cfg);

    /* prepare to receive */
    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg )
        return ENOMEM;

    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto fail;

    hexdump((unsigned char *)nlmsg, ret);

    nlhdr = &nlmsg->nlhdr;
    if (nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr, ret))
        goto fail;
    /*
    *  Received msg layout:
    *  +------------------------------------------------------------------+
    *  | NLMSGHDR | PAD | GENLMSGHDR | PAD | NLA_HDR | NLA_DATA | PAD | ...
    *  +------------------------------------------------------------------+
    */
    nla = (struct nlattr *)GENLMSG_DATA(nlhdr);
    nla_for_each_attr(nla, genlmsg_data_len(nlhdr), remain) {
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            gnl_fam = *(uint16_t *)nla_data(nla);
            break;
        }
    }

fail:
    if (nlmsg)
        free(nlmsg);
    return gnl_fam;
}

/*
    gnl_create_sock() - Create + bind a generic NL socket.
    Return: Socket descriptor or -1 on error.
*/
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
        goto fail;

    return sockd;

fail:
    if (sockd != -1)
        close(sockd);
    return -1;
}

/*
    @gnl_test_cmd() - Send test command to a custom nlmod.
    @gnl_sock: Generic NL socket.
    @family: Custom generic NL family.

    Return: 0 on success, -1 on error.
*/
int gnl_test_cmd(int gnl_sock, int family)
{
    struct nl_msg *nlmsg;
    struct nlmsghdr *nlhdr;
    struct nlattr *nla;
    struct nlattr *attrtbl[__NLMODULE_MAX];
    struct gnl_msg_cfg cfg = {
        .nlmsg_type = family,
        .nlmsg_flags = NLM_F_REQUEST,
        .gnl_cmd = NLMODULE_GET_STR,
        .gnlattr = NULL,
        .attrcount = 0,
    };
    int ret = -1;

    gnl_send_msg(gnl_sock, &cfg);

    /* prepare to receive */
    nlmsg = calloc(1, sizeof(struct nl_msg));
    if (!nlmsg)
        return ENOMEM;

    if ((ret = recv(gnl_sock, nlmsg, sizeof(struct nl_msg), 0)) == -1)
        goto fail;

    hexdump((unsigned char *)nlmsg, ret);

    nlhdr = &nlmsg->nlhdr;
    if (nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr, ret))
        goto fail;

    if ((ret = gnl_parse_attr(nlhdr, attrtbl)) <= 0)
        goto fail;

    if (attrtbl[NLMODULE_STR]) {
        nla = attrtbl[NLMODULE_STR];
        printf("Received: %s\n", (const char *)nla_data(nla));
    } else if (attrtbl[NLMODULE_U32]) {
        ;
    }

    ret = 0;
fail:
    if (nlmsg)
        free(nlmsg);

    return ret;
}

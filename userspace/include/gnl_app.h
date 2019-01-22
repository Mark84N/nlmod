#ifndef __GNL_APP_H__
#define __GNL_APP_H__

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <stdint.h>

#include "nlmod_common.h"

struct nl_msg {
    struct nlmsghdr nlhdr;
    struct genlmsghdr gnlhdr;
    uint8_t payload[4096];
};

/*
    Basically it is a nlattr-wrapper presented in a TLV-manner.
    It is done for convenient appending of the attributes to nlmsg.
    An array of gnl_attr is kept inside msg config.
*/
struct gnl_attr {
    uint16_t type;
    uint16_t len;
    void *data;
};

/*
    An attempt of generalizing sending API.
    Probably ugly, yet functional. Used to pass the most
    useful and common parameters for nlmsg construction.
*/
struct gnl_msg_cfg {
    int nlmsg_type;
    int nlmsg_flags;
    int gnl_cmd;
    /* pointer to an array of attributes */
    struct gnl_attr *gnlattr;
    /* count of attributes in an array */
    int attrcount;
};

#define GENLMSG_DATA(nlmsg) \
        ((unsigned char *)(nlmsg) + NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN))

static inline uint8_t *genlmsg_data(const struct nlmsghdr *nlh)
{
    return ((uint8_t *)(nlh) + NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN));
}

static inline uint8_t *nla_data(struct nlattr *nla)
{
    return ((uint8_t *)(nla) + NLA_HDRLEN);
}

static inline int genlmsg_data_len(const struct nlmsghdr *nlh)
{
    return nlh->nlmsg_len - NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN);
}

static inline int nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) &&
        nla->nla_len >= sizeof(*nla) &&
        nla->nla_len <= remaining;
}

static inline int nla_type_ok(struct nlattr *nla)
{
    return (((nla)->nla_type > NLMODULE_UNDEF) && \
    ((nla)->nla_type < __NLMODULE_MAX));
}

static inline struct nlattr *nla_next(struct nlattr *nla, int *remaining)
{
    unsigned int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return (struct nlattr *)((unsigned char *)nla + totlen);
}

#define nla_for_each_attr(pos, len, rem) \
    for (rem = len; nla_ok(pos, rem); \
    pos = nla_next(pos, &(rem)))

int gnl_create_sock(void);
int gnl_get_fam_id(int gnl_sock);
int gnl_test_cmd(int gnl_sock, int family);

#endif /* __GNL_APP_H__ */

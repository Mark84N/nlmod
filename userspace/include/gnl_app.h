#ifndef __GNL_APP_H__
#define __GNL_APP_H__

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <stdint.h>

#define GENLMSG_DATA(nlmsg) \
        ((unsigned char *)(nlmsg) + NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN))
#define NLA_DATA(nla) \
        ((char *)(nla) + NLA_HDRLEN)

static inline int genlmsg_data_len(const struct nlmsghdr *nh)
{
    return nh->nlmsg_len - NLMSG_ALIGN(NLMSG_HDRLEN + GENL_HDRLEN);
}

static inline int nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) &&
        nla->nla_len >= sizeof(*nla) &&
        nla->nla_len <= remaining;
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

struct nl_msg {
    struct nlmsghdr nlhdr;
    struct genlmsghdr gnlhdr;
    uint8_t payload[2048];
};

int gnl_create_sock(void);
int gnl_get_fam(int gnl_sock);
int gnl_test_cmd(int gnl_sock);

#endif /* __GNL_APP_H__ */

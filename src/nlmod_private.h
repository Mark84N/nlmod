#ifndef __NLMODULE_H__
#define __NLMODULE_H__

#include <net/netlink.h>
#include <net/genetlink.h>
/*#include "nlmod_common.h"*/

enum nlmod_msg_type {
    NLMODULE_UNDEF,
    NLMODULE_STR,
    NLMODULE_U32,
    __NLMODULE_MAX,
};

struct nlmod_hdr {
    union {
        struct {
            __u16 type;
            __u16 len;
        };
        __u32 hdr;
    };
};

#define NLMOD_CUSTOM_NAME "NLMOD CUSTOM"
#define NLMODULE_MAX (__NLMODULE_MAX - 1)
#define NLMODULE_HDR_SIZE sizeof(struct nlmod_hdr)

struct nla_policy nlmod_nla_policies[NLMODULE_MAX + 1] = {
    [NLMODULE_STR] = { .type = NLA_NUL_STRING, .len = 255, },
    [NLMODULE_U32] = { .type = NLA_U32, },
};

static struct genl_family nlmod_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = NLMODULE_HDR_SIZE,
    .name = NLMOD_CUSTOM_NAME,
    .version = 0.1,
    .maxattr = NLMODULE_MAX,
};

#endif /* __NLMODULE_H__ */
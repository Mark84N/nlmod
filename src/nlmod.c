#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netlink.h>

#include "nlmod_private.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmytro Dieiev");
MODULE_DESCRIPTION("dummy nl80211 module");

struct nla_policy nlmod_nla_policy[NLMODULE_MAX + 1] = {
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

static int nlmod_get_str(struct sk_buff *skb, struct genl_info *info)
{
    return 0;
}

static int nlmod_set_str(struct sk_buff *skb, struct genl_info *info)
{
    return 0;
}

static int nlmod_get_int(struct sk_buff *skb, struct genl_info *info)
{
    return 0;
}

static int nlmod_set_int(struct sk_buff *skb, struct genl_info *info)
{
    return 0;
}

static struct genl_ops nlmod_ops[] = {
    {
        .cmd = NLMODULE_GET_STR,
        .flags = 0,
        .policy = nlmod_nla_policy,
        .doit = nlmod_get_str,
        .dumpit = NULL,
    },
    {
        .cmd = NLMODULE_SET_STR,
        .flags = 0,
        .policy = nlmod_nla_policy,
        .doit = nlmod_set_str,
        .dumpit = NULL,
    },
    {
        .cmd = NLMODULE_GET_INT,
        .flags = 0,
        .policy = nlmod_nla_policy,
        .doit = nlmod_get_int,
        .dumpit = NULL,
    },
    {
        .cmd = NLMODULE_SET_INT,
        .flags = 0,
        .policy = nlmod_nla_policy,
        .doit = nlmod_set_int,
        .dumpit = NULL,
    },
};

static int __init nlmod__init(void)
{
    genl_register_family_with_ops(&nlmod_family, nlmod_ops);
    return 0;
}

static void __exit nlmod__deinit(void)
{
    genl_unregister_family(&nlmod_family);
}

module_init(nlmod__init);
module_exit(nlmod__deinit);

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/genetlink.h>

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
    .hdrsize = 0,//NLMODULE_HDR_SIZE,
    .name = NLMOD_CUSTOM_NAME,
    .version = 0.1,
    .maxattr = NLMODULE_MAX,
};

static char nlmod_buf[255] = "xui";
static int nlmod_int;

static int nlmod_get_str(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;

    pr_crit("%s() - event received; text=%s\n", __func__, nlmod_buf);

    msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    hdr = genlmsg_put(msg, info->snd_portid, 0, &nlmod_family, 0, NLMODULE_GET_STR);

    if (nla_put(msg, NLMODULE_STR, strlen(nlmod_buf), nlmod_buf))
        goto failure;

    // fill
    genlmsg_end(msg, hdr);
    genlmsg_reply(msg, info);

    return 0;

failure:
    genlmsg_cancel(msg, hdr);
    return -EMSGSIZE;
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

static int __init nlmod_init(void)
{
    int err = 0;
    
    err = genl_register_family_with_ops(&nlmod_family, nlmod_ops);
    if (err)
        pr_crit("%s - failed to register family\n", KBUILD_MODNAME);
    pr_crit("[%s] %s(): family \"%s\" registered.\n",
                KBUILD_MODNAME, __func__, NLMOD_CUSTOM_NAME);
    return err;
}

static void __exit nlmod_deinit(void)
{
    if (genl_unregister_family(&nlmod_family))
        pr_crit("%s - failed to unregister family\n", KBUILD_MODNAME);

    pr_crit("[%s] %s(): family \"%s\" unregistered.\n",
            KBUILD_MODNAME, __func__, NLMOD_CUSTOM_NAME);
}

module_init(nlmod_init);
module_exit(nlmod_deinit);

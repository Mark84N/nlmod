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

static int __init nlmod__init(void)
{
    return 0;
}

static void __exit nlmod__deinit(void)
{

}

module_init(nlmod__init);
module_exit(nlmod__deinit);

#include <linux/stat.h>

#include <net/genetlink.h>

static struct genl_family ext4_chain_fam;

enum ext4_chain_attrs {
    EXT4_CHAIN_ATTR_UNSPEC,
    EXT4_CHAIN_ATTR_UID,
    EXT4_CHAIN_ATTR_GID,
    EXT4_CHAIN_ATTR_ATIME,
    EXT4_CHAIN_ATTR_MTIME,
    EXT4_CHAIN_ATTR_CTIME,
    EXT4_CHAIN_ATTR_MODE,
    EXT4_CHAIN_ATTR_SIZE,
    
    __EXT4_CHAIN_ATTR_AFTER_LAST,
    NUM_EXT4_CHAIN_ATTR = __EXT4_CHAIN_ATTR_AFTER_LAST,
    EXT4_CHAIN_ATTR_MAX = __EXT4_CHAIN_ATTR_AFTER_LAST - 1
};

enum ext4_chain_commands {
    EXT4_CHAIN_CMD_SET_ATTR,
    EXT4_CHAIN_CMD_GET_ATTR,

    __EXT4_CHAIN_CMD_AFTER_LAST,
    EXT4_CHAIN_CMD_MAX = __EXT4_CHAIN_CMD_AFTER_LAST - 1
};


static const struct nla_policy ext4_chain_policy[NUM_EXT4_CHAIN_ATTR] = {
    [EXT4_CHAIN_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [EXT4_CHAIN_ATTR_UID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_GID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_ATIME] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_MTIME] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_CTIME] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_MODE] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_SIZE] = { .type = NLA_U64 },
};

int ext4_chain_set_stat(struct sk_buff *skb, struct genl_info *info)
{
    printk("ext4_chain_set_metadata");
    return 0;
};

int ext4_chain_get_stat(struct sk_buff *skb, struct genl_info *info)
{
    printk("ext4_chain_get_metadata");
    return 0;
};

static const struct genl_ops ext4_chain_ops[] = {
    {
        .cmd = EXT4_CHAIN_CMD_SET_STAT,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = ext4_chain_set_stat, 
    },
    {
        .cmd = EXT4_CHAIN_CMD_GET_STAT,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = ext4_chain_get_stat
    },
};

static struct genl_family ext4_chain_fam __ro_after_init = {
    .id = 0,
    .name = "ext4_chain",
    .hdrsize = 0,
    .version = 1,
    .maxattr = EXT4_CHAIN_ATTR_MAX,
    .policy = ext4_chain_policy,
    .module = THIS_MODULE,
    .ops = ext4_chain_ops,
    .n_ops = ARRAY_SIZE(ext4_chain_ops),
    .parallel_ops = true,
};


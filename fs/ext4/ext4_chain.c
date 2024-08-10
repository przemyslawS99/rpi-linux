#include "ext4_chain.h"

static const struct nla_policy ext4_chain_policy[NUM_EXT4_CHAIN_ATTR] = {
    [EXT4_CHAIN_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [EXT4_CHAIN_ATTR_UID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_GID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_ATIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_MTIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_CTIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_SEC] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_NSEC] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_MODE] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_SIZE] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_INO] = { .type = NLA_U64 },
};

enum ext4_chain_multicast_groups {
    EXT4_CHAIN_MCGRP_ATTR
};

static const struct genl_multicast_group ext4_chain_mcgrps[] = {
    [EXT4_CHAIN_MCGRP_ATTR] = { .name = "attr_events", },
};

static const struct genl_ops ext4_chain_ops[] = {
    {
        .cmd = EXT4_CHAIN_CMD_SET_ATTR,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = ext4_chain_set_attr, 
    },
    {
        .cmd = EXT4_CHAIN_CMD_GET_ATTR,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = ext4_chain_get_attr
    },
};

struct genl_family ext4_chain_fam = {
    .id = 0,
    .name = "ext4_chain",
    .hdrsize = 0,
    .version = 1,
    .maxattr = EXT4_CHAIN_ATTR_MAX,
    .policy = ext4_chain_policy,
    .ops = ext4_chain_ops,
    .n_ops = ARRAY_SIZE(ext4_chain_ops),
    .parallel_ops = true,
    .mcgrps = ext4_chain_mcgrps,
    .n_mcgrps = ARRAY_SIZE(ext4_chain_mcgrps),
};

int ext4_chain_set_attr(struct sk_buff *skb, struct genl_info *info)
{
    printk("ext4_chain_set_attr");
    return 0;
};

int ext4_chain_get_attr(struct sk_buff *skb, struct genl_info *info)
{
    printk("ext4_chain_get_attr");
    return 0;
};


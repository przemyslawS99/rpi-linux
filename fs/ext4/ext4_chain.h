#ifndef EXT4_CHAIN_H
#define EXT4_CHAIN_H
#include <net/genetlink.h>


enum ext4_chain_attrs {
    EXT4_CHAIN_ATTR_UNSPEC,
    EXT4_CHAIN_ATTR_UID,
    EXT4_CHAIN_ATTR_GID,
    EXT4_CHAIN_ATTR_ATIME,
    EXT4_CHAIN_ATTR_MTIME,
    EXT4_CHAIN_ATTR_CTIME,
    EXT4_CHAIN_ATTR_SEC,
    EXT4_CHAIN_ATTR_NSEC,
    EXT4_CHAIN_ATTR_MODE,
    EXT4_CHAIN_ATTR_SIZE,
    EXT4_CHAIN_ATTR_INO,
    
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

extern struct genl_family ext4_chain_fam;

int ext4_chain_set_attr(struct sk_buff *skb, struct genl_info *info);
int ext4_chain_get_attr(struct sk_buff *skb, struct genl_info *info);

#endif

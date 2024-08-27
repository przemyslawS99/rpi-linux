#ifndef EXT4_CHAIN_H
#define EXT4_CHAIN_H
#include <net/genetlink.h>

struct getattr_time {
    u64 sec;
    u32 nsec;
};

struct getattr_response {
    u64 i_ino;
    u32 i_mode;
    u32 i_uid;
    u32 i_gid;
    struct getattr_time atime;
    struct getattr_time mtime;
    struct getattr_time ctime;
};

enum ext4_chain_attrs {
    EXT4_CHAIN_ATTR_UNSPEC,
    EXT4_CHAIN_ATTR_UID,
    EXT4_CHAIN_ATTR_GID,
    EXT4_CHAIN_ATTR_ATIME,
    EXT4_CHAIN_ATTR_MTIME,
    EXT4_CHAIN_ATTR_CTIME,
    EXT4_CHAIN_ATTR_MODE,
    EXT4_CHAIN_ATTR_INO,
    EXT4_CHAIN_ATTR_STATUS_CODE,
    
    __EXT4_CHAIN_ATTR_AFTER_LAST,
    NUM_EXT4_CHAIN_ATTR = __EXT4_CHAIN_ATTR_AFTER_LAST,
    EXT4_CHAIN_ATTR_MAX = __EXT4_CHAIN_ATTR_AFTER_LAST - 1
};

enum ext4_chain_time_attrs {
    EXT4_CHAIN_TIME_ATTR_SEC,
    EXT4_CHAIN_TIME_ATTR_NSEC,

    __EXT4_CHAIN_TIME_ATTR_AFTER_LAST,
    NUM_EXT4_CHAIN_TIME_ATTR = __EXT4_CHAIN_TIME_ATTR_AFTER_LAST,
    EXT4_CHAIN_TIME_ATTR_MAX = __EXT4_CHAIN_TIME_ATTR_AFTER_LAST - 1
};

enum ext4_chain_commands {
    EXT4_CHAIN_CMD_SETPID,
    EXT4_CHAIN_CMD_SETATTR_REQUEST,
    EXT4_CHAIN_CMD_SETATTR_RESPONSE,
    EXT4_CHAIN_CMD_GETATTR_REQUEST,
    EXT4_CHAIN_CMD_GETATTR_RESPONSE,
    //EXT4_CHAIN_CMD_SETATTR_HANDLE_RESPONSE,
    //EXT4_CHAIN_CMD_GETATTR_HANDLE_RESPONSE,

    __EXT4_CHAIN_CMD_AFTER_LAST,
    EXT4_CHAIN_CMD_MAX = __EXT4_CHAIN_CMD_AFTER_LAST - 1
};

extern struct genl_family ext4_chain_fam;

int setpid(struct sk_buff *skb, struct genl_info *info);
void *send_request(struct sk_buff *msg, unsigned long i_ino, unsigned int cmd);
int handle_setattr_response(struct sk_buff *skb, struct genl_info *info);
int handle_getattr_response(struct sk_buff *skb, struct genl_info *info);
int handle_unspec_cmd(struct sk_buff *skb, struct genl_info *info);
int send_setattr_request(const struct iattr *attr, struct inode *inode);
struct getattr_response *send_getattr_request(unsigned long i_ino);
//int setattr(struct sk_buff *skb, struct genl_info *info);
//int setattr_handle_response(struct sk_buff *skb, struct genl_info *info);
//int getattr(struct sk_buff *skb, struct genl_info *info);
//int getattr_handle_response(struct sk_buff *skb, struct genl_info *info);
//int complete_setattr(u64 ino, dev_t dev, u16 status_code);

#endif

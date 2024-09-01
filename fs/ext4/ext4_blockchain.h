#ifndef EXT4_BLOCKCHAIN_H
#define EXT4_BLOCKCHAIN_H
#include <net/genetlink.h>

struct ext4b_time {
    u64 sec;
    u32 nsec;
};

struct getattr_response {
    u16 status;
    u32 i_mode;
    u32 i_uid;
    u32 i_gid;
    struct ext4b_time atime;
    struct ext4b_time mtime;
    struct ext4b_time ctime;
};

enum ext4b_attrs {
    EXT4B_ATTR_UNSPEC,
    EXT4B_ATTR_UID,
    EXT4B_ATTR_GID,
    EXT4B_ATTR_ATIME,
    EXT4B_ATTR_MTIME,
    EXT4B_ATTR_CTIME,
    EXT4B_ATTR_MODE,
    EXT4B_ATTR_INO,
    EXT4B_ATTR_STATUS,
    
    __EXT4B_ATTR_AFTER_LAST,
    NUM_EXT4B_ATTR = __EXT4B_ATTR_AFTER_LAST,
    EXT4B_ATTR_MAX = __EXT4B_ATTR_AFTER_LAST - 1
};

enum ext4b_time_attrs {
    EXT4B_TIME_ATTR_UNSPEC,
    EXT4B_TIME_ATTR_SEC,
    EXT4B_TIME_ATTR_NSEC,

    __EXT4B_TIME_ATTR_AFTER_LAST,
    NUM_EXT4B_TIME_ATTR = __EXT4B_TIME_ATTR_AFTER_LAST,
    EXT4B_TIME_ATTR_MAX = __EXT4B_TIME_ATTR_AFTER_LAST - 1
};

enum ext4b_commands {
    EXT4B_CMD_SETPID,
    EXT4B_CMD_SETATTR_REQUEST,
    EXT4B_CMD_SETATTR_RESPONSE,
    EXT4B_CMD_GETATTR_REQUEST,
    EXT4B_CMD_GETATTR_RESPONSE,

    __EXT4B_CMD_AFTER_LAST,
    EXT4B_CMD_MAX = __EXT4B_CMD_AFTER_LAST - 1
};

extern struct genl_family ext4b_fam;

u16 *ext4bd_setattr_request(const struct iattr *attr, struct inode *inode);
struct getattr_response *ext4bd_getattr_request(unsigned long i_ino);
int ext4b_stat_eq(struct kstat *stat, struct getattr_response *resp);
#endif

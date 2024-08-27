#include <net/genetlink.h>
#include <linux/fs.h>
#include <linux/hashtable.h>

#include "ext4_chain.h"

#define EXT4_CHAIN_REQ_HASH_BITS 10
static DEFINE_HASHTABLE(ext4_chain_req_table, EXT4_CHAIN_REQ_HASH_BITS);
static DECLARE_RWSEM(ext4_chain_req_table_lock);

static unsigned int ext4_chain_daemon_pid = 0;

struct ext4_chain_req_table_entry {
    unsigned long i_ino;
    struct completion comp;
    struct hlist_node ext4_chain_req_table_hlist;

    void *response;
};

static const struct nla_policy ext4_chain_policy[NUM_EXT4_CHAIN_ATTR] = {
    [EXT4_CHAIN_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [EXT4_CHAIN_ATTR_UID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_GID] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_ATIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_MTIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_CTIME] = { .type = NLA_NESTED },
    [EXT4_CHAIN_ATTR_MODE] = { .type = NLA_U32 },
    [EXT4_CHAIN_ATTR_INO] = { .type = NLA_U64 },
    [EXT4_CHAIN_ATTR_STATUS_CODE] = { .type = NLA_U16 },
};

static const struct nla_policy ext4_chain_time_policy[NUM_EXT4_CHAIN_TIME_ATTR] = {
    [EXT4_CHAIN_TIME_ATTR_SEC] = { .type = NLA_U64 },
    [EXT4_CHAIN_TIME_ATTR_NSEC] = { .type = NLA_U32 },
};

static int parse_ext4_chain_time(struct nlattr *attrs, struct getattr_time *time)
{
    struct nlattr *tb[NUM_EXT4_CHAIN_TIME_ATTR];
    int err;

    err = nla_parse_nested(tb, EXT4_CHAIN_TIME_ATTR_MAX, attrs,
            ext4_chain_time_policy, NULL);

    if (err)
        return err;

    if(!tb[EXT4_CHAIN_TIME_ATTR_SEC] || !tb[EXT4_CHAIN_TIME_ATTR_NSEC])
        return -EINVAL;

    time->sec = nla_get_u64(tb[EXT4_CHAIN_TIME_ATTR_SEC]);
    time->nsec = nla_get_u32(tb[EXT4_CHAIN_TIME_ATTR_NSEC]);
    return 0;
};

/*enum ext4_chain_multicast_groups {
    EXT4_CHAIN_MCGRP_ATTR
};

static const struct genl_multicast_group ext4_chain_mcgrps[] = {
    [EXT4_CHAIN_MCGRP_ATTR] = { .name = "attr_events", },
};*/

static const struct genl_small_ops ext4_chain_small_ops[] = {
    {
        .cmd = EXT4_CHAIN_CMD_SETPID,
        .doit = setpid,
    },
    {
        .cmd = EXT4_CHAIN_CMD_SETATTR_REQUEST,
        .doit = handle_unspec_cmd,
    },
    {
        .cmd = EXT4_CHAIN_CMD_SETATTR_RESPONSE,
        .doit = handle_setattr_response,
    },
    {
        .cmd = EXT4_CHAIN_CMD_GETATTR_REQUEST,
        .doit = handle_unspec_cmd,
    },
    {
        .cmd = EXT4_CHAIN_CMD_GETATTR_RESPONSE,
        .doit = handle_getattr_response,
    },
    /*{
        .cmd = EXT4_CHAIN_CMD_SETATTR,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = setattr,
    },
    {
        .cmd = EXT4_CHAIN_CMD_GETATTR,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = getattr,
    },
    {
        .cmd = EXT4_CHAIN_CMD_SETATTR_HANDLE_RESPONSE,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = setattr_handle_response,
    },
    {
        .cmd = EXT4_CHAIN_CMD_GETATTR_HANDLE_RESPONSE,
        .flags = 0,
        .internal_flags = 0,
        .validate = 0,
        .doit = getattr_handle_response,
    },*/
};

struct genl_family ext4_chain_fam = {
    .id = 0,
    .name = "ext4_chain",
    .hdrsize = 0,
    .version = 1,
    .maxattr = EXT4_CHAIN_ATTR_MAX,
    .policy = ext4_chain_policy,
    .small_ops = ext4_chain_small_ops,
    .n_small_ops = ARRAY_SIZE(ext4_chain_small_ops),
    .parallel_ops = true,
    //.mcgrps = ext4_chain_mcgrps,
    //.n_mcgrps = ARRAY_SIZE(ext4_chain_mcgrps),
};

int setpid(struct sk_buff *skb, struct genl_info *info)
{
    ext4_chain_daemon_pid = info->snd_portid;
    return 0;
};

int send_setattr_request(const struct iattr *attr, struct inode *inode)
{
    unsigned int ia_valid = attr->ia_valid;
    
    struct sk_buff *msg;
    void *hdr;

    int err = -EMSGSIZE;
    int *resp;

    if (!ext4_chain_daemon_pid)
        return -EINVAL;

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg) {
        err = -ENOMEM;
        goto err_out;
    }
    
    hdr = genlmsg_put(msg, 0, 0, &ext4_chain_fam, 0, EXT4_CHAIN_CMD_SETATTR_REQUEST);
    if (!hdr) {
        err = -ENOBUFS; 
        goto err_free;
    }
	
    // i_uid_update(idmap, attr, inode);
    if (attr->ia_valid & ATTR_UID &&
        nla_put_u32(msg, EXT4_CHAIN_ATTR_UID, inode->i_uid.val))
        goto err_free;
	
    // i_gid_update(idmap, attr, inode);
	if (attr->ia_valid & ATTR_GID &&
        nla_put_u32(msg, EXT4_CHAIN_ATTR_GID, inode->i_gid.val))
        goto err_free;
    
    if (ia_valid & ATTR_ATIME) { 
        struct nlattr* atime_attr = nla_nest_start(msg, EXT4_CHAIN_ATTR_ATIME);
        if (!atime_attr)
            goto err_free;
        if (nla_put_u64_64bit(msg, EXT4_CHAIN_TIME_ATTR_SEC, inode->i_atime.tv_sec, 0) ||
            nla_put_u32(msg, EXT4_CHAIN_TIME_ATTR_NSEC, inode->i_atime.tv_nsec)) {
            nla_nest_cancel(msg, atime_attr);
            goto err_free;
        } 
        nla_nest_end(msg, atime_attr);
    }
	
    if (ia_valid & ATTR_MTIME) {
        struct nlattr* mtime_attr = nla_nest_start(msg, EXT4_CHAIN_ATTR_MTIME);
        if (!mtime_attr)
            goto err_free;
        if (nla_put_u64_64bit(msg, EXT4_CHAIN_TIME_ATTR_SEC, inode->i_mtime.tv_sec, 0) ||
            nla_put_u32(msg, EXT4_CHAIN_TIME_ATTR_NSEC, inode->i_mtime.tv_nsec)) {
            nla_nest_cancel(msg, mtime_attr);
            goto err_free;
        }
        nla_nest_end(msg, mtime_attr);
    }
	
    if (ia_valid & ATTR_CTIME) {
        struct nlattr* ctime_attr = nla_nest_start(msg, EXT4_CHAIN_ATTR_CTIME);
        if (!ctime_attr)
            goto err_free;
        if (nla_put_u64_64bit(msg, EXT4_CHAIN_TIME_ATTR_SEC, inode_get_ctime_sec(inode), 0) ||
            nla_put_u32(msg, EXT4_CHAIN_TIME_ATTR_NSEC, inode_get_ctime_nsec(inode))) {
            nla_nest_cancel(msg, ctime_attr);
            goto err_free;
        }
        nla_nest_end(msg, ctime_attr);
    }
	
    if (ia_valid & ATTR_MODE &&
        nla_put_u32(msg, EXT4_CHAIN_ATTR_MODE, inode->i_mode))
        goto err_free;
    
    if (nla_put_u64_64bit(msg, EXT4_CHAIN_ATTR_INO, inode->i_ino, 0))    
        goto err_free;

    genlmsg_end(msg, hdr);

    resp = send_request(msg, inode->i_ino, EXT4_CHAIN_CMD_SETATTR_REQUEST);
     
    return *resp;
err_free:
    nlmsg_free(msg);
err_out:
    return err;
};

struct getattr_response *send_getattr_request(unsigned long i_ino)
{
    struct sk_buff *msg;
    void *hdr;
    struct getattr_response *resp;
    
    int err = -EMSGSIZE;

    if (!ext4_chain_daemon_pid)
        return -EINVAL;

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg) {
        err = -ENOMEM;
        goto err_out;
    }
    
    hdr = genlmsg_put(msg, 0, 0, &ext4_chain_fam, 0, EXT4_CHAIN_CMD_GETATTR_REQUEST);
    if (!hdr) {
        err = -ENOBUFS; 
        goto err_free;
    }
    
    if (nla_put_u64_64bit(msg, EXT4_CHAIN_ATTR_INO, i_ino, 0))    
        goto err_free;

    genlmsg_end(msg, hdr);

    resp = send_request(msg, i_ino, EXT4_CHAIN_CMD_GETATTR_REQUEST);
     
    return resp;
err_free:
    nlmsg_free(msg);
err_out:
    return NULL;
};

void *send_request(struct sk_buff *msg, unsigned long i_ino, unsigned int cmd)
{
    struct ext4_chain_req_table_entry entry;
    struct completion *comp;
    int err;
    
    if (cmd == EXT4_CHAIN_CMD_GETATTR_REQUEST)
    {
        struct ext4_chain_req_table_entry *waiting_entry;
        down_read(&ext4_chain_req_table_lock);
        hash_for_each_possible(ext4_chain_req_table, waiting_entry,
                ext4_chain_req_table_hlist, i_ino) {
            if (i_ino != waiting_entry->i_ino)
                continue;
            entry.response = waiting_entry->response;
            comp = &waiting_entry->comp;
            up_read(&ext4_chain_req_table_lock);
            goto request_already_exists;
        }
        up_read(&ext4_chain_req_table_lock);
    }
    
    entry.response = NULL;
    
    init_completion(&entry.comp);
    comp = &entry.comp;
    
    down_write(&ext4_chain_req_table_lock);
    entry.i_ino = i_ino;
    hash_add(ext4_chain_req_table, &entry.ext4_chain_req_table_hlist, entry.i_ino);
    up_write(&ext4_chain_req_table_lock);

    err = genlmsg_unicast(&init_net, msg, ext4_chain_daemon_pid);
    if (err)
        goto out;

    wait_for_completion(comp);

out:
    down_write(&ext4_chain_req_table_lock);
    hash_del(&entry.ext4_chain_req_table_hlist);
    up_write(&ext4_chain_req_table_lock);
    return entry.response;

request_already_exists:
    wait_for_completion(comp);
    return entry.response;
};

int handle_setattr_response(struct sk_buff *skb, struct genl_info *info)
{
    struct ext4_chain_req_table_entry *waiting_entry;
    int status_code;
    u64 i_ino;
    
    if (!info->attrs[EXT4_CHAIN_ATTR_STATUS_CODE] ||
        !info->attrs[EXT4_CHAIN_ATTR_INO]) {
        return -EINVAL;
    }

    status_code = nla_get_u16(info->attrs[EXT4_CHAIN_ATTR_STATUS_CODE]);
    i_ino = nla_get_u64(info->attrs[EXT4_CHAIN_ATTR_INO]);
    
    down_read(&ext4_chain_req_table_lock);
    hash_for_each_possible(ext4_chain_req_table, waiting_entry,
            ext4_chain_req_table_hlist, i_ino) {
        if (i_ino != waiting_entry->i_ino)
            continue;
        waiting_entry->response = &status_code;
        complete(&waiting_entry->comp);
        break;
    }
    up_read(&ext4_chain_req_table_lock);

    return 0;
};

int handle_getattr_response(struct sk_buff *skb, struct genl_info *info)
{
    struct getattr_response resp;
    struct ext4_chain_req_table_entry *waiting_entry;

    int err;

    if(!info->attrs[EXT4_CHAIN_ATTR_INO] ||
       !info->attrs[EXT4_CHAIN_ATTR_MODE] ||
       !info->attrs[EXT4_CHAIN_ATTR_UID] ||
       !info->attrs[EXT4_CHAIN_ATTR_GID] ||
       !info->attrs[EXT4_CHAIN_ATTR_ATIME] ||
       !info->attrs[EXT4_CHAIN_ATTR_MTIME] ||
       !info->attrs[EXT4_CHAIN_ATTR_CTIME]) {
        return -EINVAL;
    }

    resp.i_ino = nla_get_u64(info->attrs[EXT4_CHAIN_ATTR_INO]);
    resp.i_mode = nla_get_u32(info->attrs[EXT4_CHAIN_ATTR_MODE]);
    resp.i_uid = nla_get_u32(info->attrs[EXT4_CHAIN_ATTR_UID]);
    resp.i_gid = nla_get_u32(info->attrs[EXT4_CHAIN_ATTR_GID]);

    err = parse_ext4_chain_time(info->attrs[EXT4_CHAIN_ATTR_ATIME], &resp.atime);

    if (err)
        goto out;

    err = parse_ext4_chain_time(info->attrs[EXT4_CHAIN_ATTR_MTIME], &resp.mtime);

    if (err)
        goto out;

    err = parse_ext4_chain_time(info->attrs[EXT4_CHAIN_ATTR_CTIME], &resp.ctime);

    if (err)
        goto out;

out:
    down_read(&ext4_chain_req_table_lock);
    hash_for_each_possible(ext4_chain_req_table, waiting_entry,
            ext4_chain_req_table_hlist, resp.i_ino) {
        if (resp.i_ino != waiting_entry->i_ino)
            continue;
        waiting_entry->response = &resp;
        complete(&waiting_entry->comp);
        break;
    }
    up_read(&ext4_chain_req_table_lock);

    return 0;
};

int handle_unspec_cmd(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_ERR "Unknown ext4_chain cmd: %d, ignore.\n", info->genlhdr->cmd);
    return -EINVAL;
};

/*int setattr_handle_response(struct sk_buff *skb, struct genl_info *info)
{
    u16 status_code;
    u64 ino;
    dev_t dev;
    int ret;

    if (!info->attrs[EXT4_CHAIN_ATTR_STATUS_CODE] ||
        !info->attrs[EXT4_CHAIN_ATTR_INO] ||
        !info->attrs[EXT4_CHAIN_ATTR_DEV]) {
        return -EINVAL;
    }

    status_code = nla_get_u16(info->attrs[EXT4_CHAIN_ATTR_STATUS_CODE]);
    ino = nla_get_u64(info->attrs[EXT4_CHAIN_ATTR_INO]);
    dev = nla_get_u32(info->attrs[EXT4_CHAIN_ATTR_DEV]);
    
    ret = complete_setattr(ino, dev, status_code);
    
    return 0;
};

int complete_setattr(u64 ino, dev_t dev, u16 status_code)
{
    struct super_block *sb;
    struct inode *inode;
    struct ext4_inode_info *ei;
    sb = user_get_super(dev, false);
    inode = ilookup(sb, ino);
    ei = EXT4_I(inode);
    complete(ei->i_bo_compl);
    if (status_code) {
        printk("operation on blockchain failed");
    }
}

int getattr_handle_response(struct sk_buff *skb, struct genl_info *info)
{
    printk("getattr_handle_response");
    return 0;
};

int setattr(struct sk_buff *skb, struct genl_info *info)
{
    printk("setattr");
    return 0;
};

int getattr(struct sk_buff *skb, struct genl_info *info)
{
    printk("getattr");
    return 0; 
};*/

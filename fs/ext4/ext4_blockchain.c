#include <net/genetlink.h>
#include <linux/fs.h>
#include <linux/hashtable.h>

#include "ext4_blockchain.h"

#define EXT4BD_REQ_HASH_BITS 10
static DEFINE_HASHTABLE(ext4bd_req_table, EXT4BD_REQ_HASH_BITS);
static DECLARE_RWSEM(ext4bd_req_table_lock);

static unsigned int ext4bd_pid = 0;

struct ext4bd_req_table_entry {
    unsigned long i_ino;
    struct completion comp;
    struct hlist_node ext4bd_req_table_hlist;

    void *response;
};

static const struct nla_policy ext4b_policy[NUM_EXT4B_ATTR] = {
    [EXT4B_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [EXT4B_ATTR_UID] = { .type = NLA_U32 },
    [EXT4B_ATTR_GID] = { .type = NLA_U32 },
    [EXT4B_ATTR_ATIME] = { .type = NLA_NESTED },
    [EXT4B_ATTR_MTIME] = { .type = NLA_NESTED },
    [EXT4B_ATTR_CTIME] = { .type = NLA_NESTED },
    [EXT4B_ATTR_MODE] = { .type = NLA_U32 },
    [EXT4B_ATTR_INO] = { .type = NLA_U64 },
    [EXT4B_ATTR_STATUS] = { .type = NLA_U16 },
};

static const struct nla_policy ext4b_time_policy[NUM_EXT4B_TIME_ATTR] = {
    [EXT4B_TIME_ATTR_SEC] = { .type = NLA_U64 },
    [EXT4B_TIME_ATTR_NSEC] = { .type = NLA_U32 },
};

static int parse_ext4b_time(struct nlattr *attrs, struct ext4b_time *time)
{
    struct nlattr *tb[NUM_EXT4B_TIME_ATTR];
    int err;

    err = nla_parse_nested(tb, EXT4B_TIME_ATTR_MAX, attrs,
            ext4b_time_policy, NULL);

    if (err)
        return err;

    if(!tb[EXT4B_TIME_ATTR_SEC] || !tb[EXT4B_TIME_ATTR_NSEC])
        return -EINVAL;

    time->sec = nla_get_u64(tb[EXT4B_TIME_ATTR_SEC]);
    time->nsec = nla_get_u32(tb[EXT4B_TIME_ATTR_NSEC]);
    return 0;
};


static int setpid(struct sk_buff *skb, struct genl_info *info)
{
    ext4bd_pid = info->snd_portid;
    printk(KERN_DEBUG "setpid: Daemon pid successfuly set: %d", ext4bd_pid);
    return 0;
};

static void *send_request(struct sk_buff *msg, unsigned long i_ino, unsigned int cmd)
{
    struct ext4bd_req_table_entry entry;
    struct completion *comp;
    int err;
    
    if (cmd == EXT4B_CMD_GETATTR_REQUEST)
    {
        struct ext4bd_req_table_entry *waiting_entry;
        down_read(&ext4bd_req_table_lock);
        hash_for_each_possible(ext4bd_req_table, waiting_entry,
                ext4bd_req_table_hlist, i_ino) {
            if (i_ino != waiting_entry->i_ino)
                continue;
            entry.response = waiting_entry->response;
            comp = &waiting_entry->comp;
            up_read(&ext4bd_req_table_lock);
            goto request_already_exists;
        }
        up_read(&ext4bd_req_table_lock);
    }
    
    entry.response = NULL;
    
    init_completion(&entry.comp);
    comp = &entry.comp;
    
    down_write(&ext4bd_req_table_lock);
    entry.i_ino = i_ino;
    hash_add(ext4bd_req_table, &entry.ext4bd_req_table_hlist, entry.i_ino);
    up_write(&ext4bd_req_table_lock);

    err = genlmsg_unicast(&init_net, msg, ext4bd_pid);

    if (err)
        goto out;
    
    printk(KERN_DEBUG "send_request: Message sent. i_ino: %lu. Waiting for completion...\n", i_ino);
    wait_for_completion(comp);
    printk(KERN_DEBUG "send_request: Request completed. i_ino: %lu.\n", i_ino);
out:
    down_write(&ext4bd_req_table_lock);
    hash_del(&entry.ext4bd_req_table_hlist);
    up_write(&ext4bd_req_table_lock);
    return entry.response;

request_already_exists:
    wait_for_completion(comp);
    return entry.response;
};

static int ext4bd_prep_setattr_req_msg(struct sk_buff *msg, const struct iattr *attr, struct inode *inode)
{
    unsigned int ia_valid = attr->ia_valid;
    
    void *hdr;
    
    int err = -EMSGSIZE; 
    
    hdr = genlmsg_put(msg, 0, 0, &ext4b_fam, 0, EXT4B_CMD_SETATTR_REQUEST);
    if (!hdr) {
        err = -ENOBUFS; 
        goto err_out;
    }
    if (attr->ia_valid & ATTR_UID &&
        nla_put_u32(msg, EXT4B_ATTR_UID, inode->i_uid.val))
        goto err_out;
	
	if (attr->ia_valid & ATTR_GID &&
        nla_put_u32(msg, EXT4B_ATTR_GID, inode->i_gid.val))
        goto err_out;
    
    if (ia_valid & ATTR_ATIME) { 
        struct nlattr* atime_attr = nla_nest_start(msg, EXT4B_ATTR_ATIME);
        if (!atime_attr)
            goto err_out;
        if (nla_put_u64_64bit(msg, EXT4B_TIME_ATTR_SEC, inode->i_atime.tv_sec, 0) ||
            nla_put_u32(msg, EXT4B_TIME_ATTR_NSEC, inode->i_atime.tv_nsec)) {
            nla_nest_cancel(msg, atime_attr);
            goto err_out;
        } 
        nla_nest_end(msg, atime_attr);
    }
	
    if (ia_valid & ATTR_MTIME) {
        struct nlattr* mtime_attr = nla_nest_start(msg, EXT4B_ATTR_MTIME);
        if (!mtime_attr)
            goto err_out;
        if (nla_put_u64_64bit(msg, EXT4B_TIME_ATTR_SEC, inode->i_mtime.tv_sec, 0) ||
            nla_put_u32(msg, EXT4B_TIME_ATTR_NSEC, inode->i_mtime.tv_nsec)) {
            nla_nest_cancel(msg, mtime_attr);
            goto err_out;
        }
        nla_nest_end(msg, mtime_attr);
    }
	
    if (ia_valid & ATTR_CTIME) {
        struct nlattr* ctime_attr = nla_nest_start(msg, EXT4B_ATTR_CTIME);
        if (!ctime_attr)
            goto err_out;
        if (nla_put_u64_64bit(msg, EXT4B_TIME_ATTR_SEC, inode_get_ctime_sec(inode), 0) ||
            nla_put_u32(msg, EXT4B_TIME_ATTR_NSEC, inode_get_ctime_nsec(inode))) {
            nla_nest_cancel(msg, ctime_attr);
            goto err_out;
        }
        nla_nest_end(msg, ctime_attr);
    }
	
    if (ia_valid & ATTR_MODE &&
        nla_put_u32(msg, EXT4B_ATTR_MODE, inode->i_mode))
        goto err_out;
    
    if (nla_put_u64_64bit(msg, EXT4B_ATTR_INO, inode->i_ino, 0))    
        goto err_out;
    genlmsg_end(msg, hdr);
    return 0;

err_out:
    nlmsg_free(msg);
    return err;
};

u16 *ext4bd_setattr_request(const struct iattr *attr, struct inode *inode)
{
    struct sk_buff *msg;
    u16 *resp = NULL;
    
    if (!ext4bd_pid) {
        printk(KERN_DEBUG "ext4bd_setattr_request: No running daemon.\n");
        goto out;
    }
    
    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        goto out;
    
    if (ext4bd_prep_setattr_req_msg(msg, attr, inode) < 0)
        goto out;

    resp = send_request(msg, inode->i_ino, EXT4B_CMD_SETATTR_REQUEST);
out:
    return resp;
};

static int ext4bd_prep_getattr_req_msg(struct sk_buff *msg, unsigned long i_ino)
{
    void *hdr;
    
    int err = -EMSGSIZE;
    
    hdr = genlmsg_put(msg, 0, 0, &ext4b_fam, 0, EXT4B_CMD_GETATTR_REQUEST);
    if (!hdr) {
        err = -ENOBUFS; 
        goto err_out;
    }
    
    if (nla_put_u64_64bit(msg, EXT4B_ATTR_INO, i_ino, 0))    
        goto err_out;

    genlmsg_end(msg, hdr);
    return 0;

err_out:
    nlmsg_free(msg);
    return err;
};

struct getattr_response *ext4bd_getattr_request(unsigned long i_ino)
{
    struct sk_buff *msg;
    struct getattr_response *resp = NULL;
    
    if (!ext4bd_pid) {
        printk(KERN_DEBUG "getattr_request: No running daemon.\n");
        goto out;
    }

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        goto out;

    if (ext4bd_prep_getattr_req_msg(msg, i_ino) < 0)
        goto out;

    resp = send_request(msg, i_ino, EXT4B_CMD_GETATTR_REQUEST);
     
out:
    return resp;
};

static int handle_setattr_response(struct sk_buff *skb, struct genl_info *info)
{
    struct ext4bd_req_table_entry *entry;
    u64 i_ino;

    int ret = 0;

    if (!info->attrs[EXT4B_ATTR_STATUS] ||
        !info->attrs[EXT4B_ATTR_INO]) {
        return -EINVAL;
    }

    i_ino = nla_get_u64(info->attrs[EXT4B_ATTR_INO]);
    
        down_read(&ext4bd_req_table_lock);
    hash_for_each_possible(ext4bd_req_table, entry,
            ext4bd_req_table_hlist, i_ino) {
        if (i_ino != entry->i_ino)
            continue;

        entry->response = kmalloc(sizeof(u16), GFP_KERNEL);
        if (!entry->response){
            ret = -ENOMEM;
            goto out;
        }        
        *(u16 *)entry->response = nla_get_u16(info->attrs[EXT4B_ATTR_STATUS]); 
out:
        complete(&entry->comp);
        break;
    }
    up_read(&ext4bd_req_table_lock);

    return ret;
};

static int handle_getattr_response(struct sk_buff *skb, struct genl_info *info)
{
    struct ext4bd_req_table_entry *entry;
    struct getattr_response *resp;
    u64 i_ino;
    int ret = 0;

    if(!info->attrs[EXT4B_ATTR_STATUS] ||
       !info->attrs[EXT4B_ATTR_INO] ||
       !info->attrs[EXT4B_ATTR_MODE] ||
       !info->attrs[EXT4B_ATTR_UID] ||
       !info->attrs[EXT4B_ATTR_GID] ||
       !info->attrs[EXT4B_ATTR_ATIME] ||
       !info->attrs[EXT4B_ATTR_MTIME] ||
       !info->attrs[EXT4B_ATTR_CTIME]) {
        return -EINVAL;
    }

    i_ino = nla_get_u64(info->attrs[EXT4B_ATTR_INO]);

    down_read(&ext4bd_req_table_lock);
    hash_for_each_possible(ext4bd_req_table, entry,
            ext4bd_req_table_hlist, i_ino) {
        if (i_ino != entry->i_ino)
            continue;
        
        entry->response = kmalloc(sizeof(struct getattr_response), GFP_KERNEL);
        if (!entry->response){
            ret = -ENOMEM;
            goto out;
        }

        resp = (struct getattr_response *)entry->response;
        
        resp->status = nla_get_u16(info->attrs[EXT4B_ATTR_STATUS]); 
        resp->i_mode = nla_get_u32(info->attrs[EXT4B_ATTR_MODE]); 
        resp->i_uid = nla_get_u32(info->attrs[EXT4B_ATTR_UID]); 
        resp->i_gid = nla_get_u32(info->attrs[EXT4B_ATTR_GID]); 
        
        ret = parse_ext4b_time(info->attrs[EXT4B_ATTR_ATIME], &resp->atime);
        if (ret)
            goto out;

        ret = parse_ext4b_time(info->attrs[EXT4B_ATTR_MTIME], &resp->mtime);
        if (ret)
            goto out;

        ret = parse_ext4b_time(info->attrs[EXT4B_ATTR_CTIME], &resp->ctime);
        if (ret)
            goto out;
out:
        complete(&entry->comp);
        break;
    }
    up_read(&ext4bd_req_table_lock);

    return ret;
};

static int handle_unspec_cmd(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_ERR "Unknown ext4_chain cmd: %d, ignore.\n", info->genlhdr->cmd);
    return -EINVAL;
};

static const struct genl_small_ops ext4b_small_ops[] = {
    {
        .cmd = EXT4B_CMD_SETPID,
        .doit = setpid,
    },
    {
        .cmd = EXT4B_CMD_SETATTR_REQUEST,
        .doit = handle_unspec_cmd,
    },
    {
        .cmd = EXT4B_CMD_SETATTR_RESPONSE,
        .doit = handle_setattr_response,
    },
    {
        .cmd = EXT4B_CMD_GETATTR_REQUEST,
        .doit = handle_unspec_cmd,
    },
    {
        .cmd = EXT4B_CMD_GETATTR_RESPONSE,
        .doit = handle_getattr_response,
    },
};

struct genl_family ext4b_fam = {
    .id = 0,
    .name = "ext4_blockchain",
    .hdrsize = 0,
    .version = 1,
    .maxattr = EXT4B_ATTR_MAX,
    .policy = ext4b_policy,
    .small_ops = ext4b_small_ops,
    .n_small_ops = ARRAY_SIZE(ext4b_small_ops),
    .parallel_ops = true,
};



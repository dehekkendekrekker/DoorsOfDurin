#ifndef _DOD_MAIN_H
#define _DOD_MAIN_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>

#define SHA256_DIGEST_LENGTH 32

#define CMD_ADD 0
#define CMD_DEL 1

/* ERRORS */

#define E_KEYLEN 1
#define E_INVKEY 2
#define E_HASH 3
#define E_HASHLEN 4
#define E_NOTUDP 5
#define E_INVCMD 6
#define E_READERR 7
#define E_NOTANUMBER 8
#define E_INCSIZE 9
#define E_VAL 10
#define E_EXISTS 11
#define E_PROTO 12

#define SETTING_BUF_SIZE 256 + 1

#define PROCFS_LINEBUF_SIZE 512



typedef struct auth {
    __be32 ip;
    ktime_t ts;
} auth;


void init_timer(void);

int handle_cmd_input(size_t, const char*,char*);
int validate_port(char*, uint16_t*);

bool isvalidIPv4(const char*);

bool check_auth_attempt(__be32, char *);
int extract_payload(struct sk_buff *, char *);

uint16_t get_dport(struct sk_buff *skb);
bool is_authorized(__be32);
bool has_access(struct sk_buff *);
void give_access(__be32 saddr);
bool is_port_accessible(uint16_t);

void register_ipv4_hook(void);
int packet_received(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void register_ipv4_hook(void);
void unregister_ipv4_hook(void);
int __init dod_init(void);
void __exit dod_exit(void);


/* proc fs functions */
ssize_t proc_read_secret(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_secret(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ipv4_authorized(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ipv4_authorized(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ports_invisible(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ports_invisible(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ports_visible(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ports_visible(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ipv4_icmp(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ipv4_icmp(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ipv4_udp(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ipv4_udp(struct file*, const char*, size_t, loff_t*);

ssize_t proc_read_ipv4_tcp(struct file*, char*, size_t, loff_t*);
ssize_t proc_write_ipv4_tcp(struct file*, const char*, size_t, loff_t*);




ssize_t proc_read_char(char*, size_t size, loff_t*, char *src);
ssize_t proc_write_char(const char *buf, size_t size, loff_t *offset, char *dest, char *);

ssize_t proc_read_int(char*, size_t size, loff_t*, int src);
ssize_t proc_write_int(const char *buf, size_t size, loff_t *offset, int *dest, char *);


// String functions
bool chkwl(char*, char*);
void rmnl(char*);



#endif

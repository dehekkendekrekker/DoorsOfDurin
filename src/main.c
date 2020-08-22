#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include "main.h"
#include "crypto.h"
#include "algo.h"


#define KEY_WORD_LENGTH 8
#define KEY_BYTE_LENGTH 32


typedef struct rnode {
    char nitems;
    struct rnode **items;
} rnode;

static struct nf_hook_ops *nfho_ipv4;

static queue authips;
static queue visible_ports;
static queue invisible_ports;

// Settings 
static char secret[SETTING_BUF_SIZE] = "secret"; // Todo turn this into a parameter
static bool icmp_enabled = 1;
static bool udp_enabled = 1;
static bool tcp_enabled = 1;


static struct proc_dir_entry *proc_ent_dod;
static struct proc_dir_entry *proc_ent_ipv4;
static struct proc_dir_entry *proc_ent_ports;
static struct proc_dir_entry *proc_ent_secret;
static struct proc_dir_entry *proc_ent_ipv4_authorized;
static struct proc_dir_entry *proc_ent_ports_visible;
static struct proc_dir_entry *proc_ent_ports_invisible;

static struct proc_dir_entry *proc_ent_ipv4_icmp;
static struct proc_dir_entry *proc_ent_ipv4_udp;
static struct proc_dir_entry *proc_ent_ipv4_tcp;



/**
 * Valid character arrays. Used for input validation
 */
static char valid_alphanum[] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "`1234567890~-=!@#$%^&*()_+"
                            "[]\\{}|;':\",./<>? \n\r";

                            
static char valid_num[] = "0123456789";



static struct file_operations proc_secret_fops = {
     .owner = THIS_MODULE,
     .read = proc_read_secret,
     .write = proc_write_secret
};

static struct file_operations proc_ipv4_authorized_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ipv4_authorized,
    .write = proc_write_ipv4_authorized
};
 
static struct file_operations proc_ports_visible_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ports_visible,
    .write = proc_write_ports_visible
};
  
static struct file_operations proc_ports_invisible_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ports_invisible,
    .write = proc_write_ports_invisible
};
 
static struct file_operations proc_ipv4_icmp_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ipv4_icmp,
    .write = proc_write_ipv4_icmp
};
 
static struct file_operations proc_ipv4_udp_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ipv4_udp,
    .write = proc_write_ipv4_udp
};
 
static struct file_operations proc_ipv4_tcp_fops = {
    .owner = THIS_MODULE,
    .read = proc_read_ipv4_tcp,
    .write = proc_write_ipv4_tcp
};
 
/**
 * This function is a hook function that is called when is packet is received.
 * Currently this is only the case for IPv4 packets
 */
int packet_received(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    int result;
    char rhashbuf[SHA256_DIGEST_LENGTH];

    // If the socket buffer is unset, drop the packet
    if (!skb) goto drop;

    // If the source address has authorized before, accept the packet
    if (has_access(skb)) goto accept;

    // ******************************
    // At this point the source IPv4 address is unauthorized. The following logic deals
    // with authoriation only.
    // ******************************
    
    // Drop the packet if the shared secret is not set
    if (*secret == 0) goto drop;

    // Perform the authentication check
    if ((result = extract_payload(skb, rhashbuf)) < 0) goto drop;

    // Get IP header
    iph = ip_hdr(skb);

    // rhashbuf now contains a 32 byte string, which is NOT null terminated. Beware
    if (check_auth_attempt(iph->saddr, rhashbuf) == true) {
        printk(KERN_INFO "DOD: Access granted to %pI4", &iph->saddr);
        give_access(iph->saddr);
    }

    goto drop;

drop:
    return NF_DROP;

accept:
    return NF_ACCEPT;
}

/*
 * Extracts the payload from a UDP packet
 */
int extract_payload(struct sk_buff *skb, char *buffer) {
    char *tail, *ppayload;
    int payloadlen;
    struct udphdr *udph;
    struct iphdr *iph;

    iph = ip_hdr(skb);
    udph = udp_hdr(skb);

    // We'll only accept UDP packets to unlock
    if (iph->protocol != IPPROTO_UDP) return -E_NOTUDP;

    // Extract the payload from the udp packet
    tail = skb_tail_pointer(skb);
    ppayload = (char*)udph + sizeof(udph);
    payloadlen = tail - ppayload;

    // We'll only accept packets of the right size
    if (payloadlen != 32) return -E_HASHLEN;

    memcpy(buffer, ppayload, 32);

    return 0;
}


/**
 * Generated the sha256 hash of the concatenstion of the ip address and the secret.
 * Then this hash is compared with the user supplied payload.
 * If it's the same, the check passes, if not it fails.
 */
bool check_auth_attempt(__be32 ip, char *rhashbuf) {
    char digest[SHA256_DIGEST_LENGTH];
    char secretbuf[4 + SETTING_BUF_SIZE]; 
    int secretlen, result;

    memcpy(secretbuf, &ip, 4);
    strncpy(secretbuf + 4, secret, SETTING_BUF_SIZE);

    // Calculate length of the data
    secretlen = strlen(secret) + 4;

    // Calculate sha256sum of data
    if ((result = sha256sum(secretbuf, secretlen, digest)) < 0) {
        printk(KERN_WARNING "DOD: An error occured while hashing. Code: %i", result);
        goto exit_false;
    }

#ifdef DOD_DEBUG
    printk(KERN_ERR "SHA256(%pI4,%s): %*phC", &ip, secret, SHA256_DIGEST_LENGTH, (void*)digest);
    printk(KERN_ERR "Received hash: %*phC", SHA256_DIGEST_LENGTH, (void*)rhashbuf);
#endif

    // Return true when the hashes match
    if (strncmp(rhashbuf, digest, SHA256_DIGEST_LENGTH) == 0) return true;

    // Return false by default

exit_false:    
    return false;
}

/**
 * Gets the destination port for a packet using the UDP or TCP protocol
 */
uint16_t get_dport(struct sk_buff *skb) {
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        return ntohs(udph->dest);
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        return ntohs(tcph->dest);
    }

    printk(KERN_WARNING "DOD: Packet with unsupported protocol passed");
    return -E_PROTO;
}

bool is_port_accessible(uint16_t port) {
    qlink *pqlnk;
    uint16_t *pval;

    // If both access lists are empty, they are uninitialized and all ports are reachable
    if (visible_ports.cnt == 0 && invisible_ports.cnt == 0) 
        goto ret_true;

    // Visisble port list takes preference over invisbile port list
    if (visible_ports.cnt > 0) {
        queue_rewind(&visible_ports);
        while ((pqlnk = queue_nexti(&visible_ports)) != NULL) {
            pval = pqlnk->pitem;
            if (*pval == port) goto ret_true;
        }
        goto ret_false;
    }

    if (invisible_ports.cnt > 0) {
        queue_rewind(&invisible_ports);
        while ((pqlnk = queue_nexti(&invisible_ports)) != NULL) {
            pval = pqlnk->pitem;
            if (*pval == port) goto ret_false;
        }
        goto ret_true;
    }


ret_true:
    return true;
ret_false:
    return false;
}



bool is_authorized(__be32 ip) {
    qlink *pqlink;
    auth *pauth;

     // Loop through the list of authorized ips, to see if the supplied addresss is 
    // present in the list
    queue_rewind(&authips);
    while ((pqlink = queue_nexti(&authips)) != NULL) {
        pauth = pqlink->pitem;
        if (pauth->ip == ip) return true;
    }
    
    // We've reached the end of the list, but the source ip address is not in the  list
    return false;
}

/**
 * Checks if the supplied ip has access, and if the port is reachable
 */
bool has_access(struct sk_buff *skb) {
    struct iphdr *iph;
    uint16_t dport;
    bool authorized;

    iph = ip_hdr(skb);

    // Check if the source address is authorized to the system
    authorized = is_authorized(iph->saddr);

    // authorized IP's have full access to the port range, and don't deal with ACL's
    if (authorized) goto ret_true;

    /* This block checks for each protocol what to do with the packet.
     * If the protocol specific stetting is 1, the go on to the next step. For ICMP this means allow
     * for UDP and TCP, this means the ACL (visible/invisble) is checked.
     * The default is drop
     */
    switch(iph->protocol) {
        case IPPROTO_ICMP:
            if (icmp_enabled) { 
                goto ret_true;
            } else {
                goto ret_false;
            }
        case IPPROTO_TCP:
            if(tcp_enabled) {
                goto check_acl;
            } else {
                goto ret_false;
            }
        case IPPROTO_UDP:
            if (udp_enabled){
                goto check_acl;
            } else {
                goto ret_false;
            }
        // All other protocols
        default:
            goto ret_false;

    }

// This section takes into account the white/blacklisting of the requested port
check_acl:
        // Here's where unauthorized IP's are handled
    dport = get_dport(skb);
    if (is_port_accessible(dport))
        goto ret_true;

    // Deny by default
    goto ret_false;

ret_true:
    return true;

ret_false:
    return false;
}

/**
 * Gives an IP address access to the system as DoD was not in place
 */
void give_access(__be32 addr) {
    auth *pauth;

    pauth = kcalloc(1, sizeof(auth), GFP_KERNEL);

    pauth->ip = addr;
    pauth->ts = ktime_get_real();

    queue_pushi(&authips, pauth);
}


void register_ipv4_hook(void) {
    nfho_ipv4 = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	/* Initialize netfilter hook */
	nfho_ipv4->hook 	    = (nf_hookfn*)packet_received;		/* hook function */
	nfho_ipv4->hooknum 	    = NF_INET_LOCAL_IN;		/* Packets that have been determined to be for the local system */
	nfho_ipv4->pf 	        = PF_INET;			/* IPv4 */
	nfho_ipv4->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho_ipv4);
}

void unregister_ipv4_hook(void) {
    nf_unregister_net_hook(&init_net, nfho_ipv4);
	kfree(nfho_ipv4);
}

/**
 * Handles command input. Cmd input specifies a command and a parameter
 */
int handle_cmd_input(size_t len, const char *userbuf, char *valbuf) {
    int cmd;
    char linebuf[PROCFS_LINEBUF_SIZE] = {0};


    if (copy_from_user(linebuf, userbuf, len) != 0) {
        goto readerror;
    }

    // Determine which command is requested, and place the value
    // into *valbuf
    if (sscanf(linebuf, "add %s", valbuf) > 0) {
        cmd = CMD_ADD;
    } else if (sscanf(linebuf, "del %s", valbuf) > 0) {
        cmd = CMD_DEL;
    } else {
        goto invcmd;
    }

    // Strip newlines
    rmnl(valbuf);

    // End of happy path
    return cmd;

    // Error handling

readerror:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Error while reading from userbuffer");
#endif
    return -E_READERR;
invcmd:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Invalid command specified");
#endif
    return -E_INVCMD;
}

/*
 * Validates a port
 */
int validate_port(char *valbuf, uint16_t *port) {
    // Validate the number
    if (!chkwl(valid_num, valbuf))
        goto e_notanumber;

    // Length validation
    if (strlen(valbuf) < 1 || strlen(valbuf) > 5)
        goto e_incorrect_size;


    // Convert the string port into an integer port
    if (sscanf(valbuf, "%hu", (short unsigned int*)port) == 0) 
        goto e_validation;

    // All ok
    return 0;


e_notanumber:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Supplied argument is not a number");
#endif
    return -E_NOTANUMBER;

e_incorrect_size:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Supplied argument does not have correct size");
#endif
    return -E_INCSIZE;

e_validation:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Supplied argument is not a port number");
#endif
    return -E_VAL;
}


/**
 * Adds a port to a queue
 */
int add_port(queue *pq, uint16_t port) {
    qlink *pqlnk;
    uint16_t *pval;


    // See if the port already exists in the queue
    queue_rewind(pq);
    while ((pqlnk = queue_nexti(pq)) != NULL) {
        pval = pqlnk->pitem;
        if (*pval == port) goto e_exists;
    }

    // It doesn't, so add it
    pval = kcalloc(1, sizeof(uint16_t), GFP_KERNEL);
    *pval = port;
    queue_pushi(pq, pval);

    return 0;

e_exists:
#ifdef DOD_DEBUG
    printk(KERN_ERR "Port already exists in queue");
#endif
    return -E_EXISTS;

}

/**
 * Deletes a port from the supplied queue
 */
void del_port(queue *pq, uint16_t port) {
    qlink *pqlnk;
    uint16_t *pval;

    queue_rewind(pq);
    while ((pqlnk = queue_nexti(pq)) != NULL) {
        pval = pqlnk->pitem;
        // If it does, delete the reference and unlink the qlink
        if (*pval == port) {
            kfree(pqlnk->pitem);
            queue_unlink(pq, pqlnk);
        }
    }
}

/************************
 * PROCFS ENTRIES
 *************************/



/**
 * Handles a read from /proc/dod/secret
 */
ssize_t proc_read_secret(struct file* file, char* buf, size_t len, loff_t* offset) {
   len =  proc_read_char(buf, len, offset, secret); 
   *offset = len;
   return len;
}


/**
 * Handles a write to /proc/dod/secret
 */
ssize_t proc_write_secret(struct file* file, const char* buf, size_t len, loff_t* offset) {
    len =  proc_write_char(buf, len, offset, secret, valid_alphanum);
    *offset = len;
    return len;
}

/**
 * Handles a read request on /proc/dod/ipv4/authorized
 */
ssize_t proc_read_ipv4_authorized(struct file* file, char* buf, size_t size, loff_t* offset) {
    char *pbuf;
    auth *pauth;
    qlink *pqlink;
    int len;

    // Nothing to display? Return ..
    if (authips.cnt == 0) return 0;

    // We're not doing chunk style reading
    if (*offset > 0) return 0;

    // Allocate space to display the IP's that have axx to the system
    pbuf = kcalloc(authips.cnt, 15, GFP_KERNEL);

    queue_rewind(&authips);
    while ((pqlink = queue_nexti(&authips)) != NULL){
        pauth = pqlink->pitem;
        sprintf(pbuf + strlen(pbuf), "%pI4\n", &pauth->ip);
    }

    len = strlen(pbuf);

    if (copy_to_user(buf, pbuf, len) != 0) {
#ifdef DOD_DEBUG
        printk(KERN_ERR "An error occured while reading");
#endif
        kfree(pbuf);
        *offset = 0;
        return 0;
    }

    kfree(pbuf);
    *offset = len;
    return len;
}

ssize_t proc_write_ipv4_authorized(struct file* file, const char* buf, size_t size, loff_t* offset) {
    char linebuf[PROCFS_LINEBUF_SIZE] = {0};
    char ipbuf[PROCFS_LINEBUF_SIZE] = {0};

    __be32 ip;
    int len;
    qlink *pqlnk;
    auth *pauth;
    enum cmds {add, del} cmd;


    // No offset writing
    if (*offset > 0) return 0;

    len = min(size, (size_t)PROCFS_LINEBUF_SIZE);
    if (copy_from_user(linebuf, buf, len) != 0) {
#ifdef DOD_DEBUG 
        printk(KERN_ERR "Error while reading from userbuffer");
#endif
        goto proc_write_ipv4_authorized_exit;
    }

    // Handle add <ip> command
    if (sscanf(linebuf, "add %s", ipbuf) > 0) {
        cmd = add;
    } else if (sscanf(linebuf, "del %s", ipbuf) > 0) {
        cmd = del;
    } else {
        // Some garblegarble has been supplied. Exit
        goto proc_write_ipv4_authorized_exit;
    }


    // Remove newlines
    rmnl(ipbuf);

    // Validate the IP address
    if (!isvalidIPv4(ipbuf)) 
        goto proc_write_ipv4_authorized_exit;

    // Convert the string ip address to ip
    ip = in_aton(ipbuf);

    // See if the qlink is part of the queue
    queue_rewind(&authips);
    switch (cmd) {
        case add:
            // See if the IP we want to add to the list not already exists
            while ((pqlnk = queue_nexti(&authips)) != NULL) {
                pauth = pqlnk->pitem; 
                if (pauth->ip == ip) goto proc_write_ipv4_authorized_exit;
             }

            // It doesn't, so add it
            pauth = kcalloc(1, sizeof(auth), GFP_KERNEL);
            pauth->ip = ip;
            queue_pushi(&authips, pauth);

            break;
        case del:
            // Look up the ip address in the list. This will remove all ipv4s from the auth list that match
            // the supplied ip. They should be unique, but this weeds them out
            while ((pqlnk = queue_nexti(&authips)) != NULL) {
                pauth = pqlnk->pitem;
                // If it does, delete the reference and unlink the qlink
                if (pauth->ip == ip) {
                    kfree(pqlnk->pitem);
                    queue_unlink(&authips, pqlnk);
                }
            }

            break;
    }


// All done at this point

proc_write_ipv4_authorized_exit:
    *offset = len;
    return len;
}






/**
 * Handles a read operation on /proc/dod/ports/visible
 */
ssize_t proc_read_ports_visible(struct file *file,  char* buf, size_t size, loff_t* offset) {
    char *pbuf;
    qlink *pqlnk;
    uint16_t *pval;
    int len;

    // Nope
    if (*offset > 0) goto exit;

    if (visible_ports.cnt == 0) goto exit;

    pbuf = kcalloc(7, visible_ports.cnt, GFP_KERNEL);
    queue_rewind(&visible_ports);
    while ((pqlnk = queue_nexti(&visible_ports)) != NULL) {
        pval = pqlnk->pitem;
        snprintf(pbuf + strlen(pbuf), 7, "%hu\n", *pval);
    }

    len = strlen(pbuf);

    if (copy_to_user(buf, pbuf, len) != 0)
        goto e_readerror;

    // All good
    kfree(pbuf);
    *offset = len;
    return len;

    
e_readerror:
    kfree(pbuf);
#ifdef DOD_DEBUG
    printk(KERN_ERR "Read error");
#endif
exit:
    return 0;
}


/**
 * Handles a write operation to the /proc/dod/ports/visible path
 */
ssize_t proc_write_ports_visible(struct file *file, const char *buf, size_t size, loff_t *offset) {
    char valbuf[PROCFS_LINEBUF_SIZE] = {0};
    uint16_t port;
    int cmd;
    size_t len;
 
    // No offset writing
    if (*offset > 0) return 0;

    len = min(size, (size_t)PROCFS_LINEBUF_SIZE);
    // Extract command and string value of parameter
    if ((cmd = handle_cmd_input(size, buf, valbuf)) < 0) 
        goto exit;

    // Validate parameter, and assign to correct type
    if (validate_port(valbuf, &port) < 0) 
        goto exit;
 

    switch (cmd) {
        case CMD_ADD:
            add_port(&visible_ports, port);
            break;
        case CMD_DEL:
            del_port(&visible_ports, port);
            break;
    }

// All done at this point

exit:
    *offset = len;
    return len;
}




ssize_t proc_read_ports_invisible(struct file *file,  char* buf, size_t size, loff_t* offset) {
    char *pbuf;
    qlink *pqlnk;
    uint16_t *pval;
    int len;

    // Nope
    if (*offset > 0) goto exit;

    if (invisible_ports.cnt == 0) goto exit;

    pbuf = kcalloc(7, invisible_ports.cnt, GFP_KERNEL);
    queue_rewind(&invisible_ports);
    while ((pqlnk = queue_nexti(&invisible_ports)) != NULL) {
        pval = pqlnk->pitem;
        snprintf(pbuf + strlen(pbuf), 7, "%hu\n", *pval);
    }

    len = strlen(pbuf);

    if (copy_to_user(buf, pbuf, len) != 0)
        goto e_readerror;

    // All good
    kfree(pbuf);
    *offset = len;
    return len;

    
e_readerror:
    kfree(pbuf);
#ifdef DOD_DEBUG
    printk(KERN_ERR "Read error");
#endif
exit:
    return 0;
}


ssize_t proc_write_ports_invisible(struct file *file, const char *buf, size_t size, loff_t *offset) {
    char valbuf[PROCFS_LINEBUF_SIZE] = {0};
    uint16_t port;
    int cmd;
    size_t len;
 
    // No offset writing
    if (*offset > 0) return 0;


    len = min(size, (size_t)PROCFS_LINEBUF_SIZE);
    // Extract command and string value of parameter
    if ((cmd = handle_cmd_input(size, buf, valbuf)) < 0) 
        goto exit;

    // Validate parameter, and assign to correct type
    if (validate_port(valbuf, &port) < 0) 
        goto exit;
 

    switch (cmd) {
        case CMD_ADD:
            add_port(&invisible_ports, port);
            break;
        case CMD_DEL:
            del_port(&invisible_ports, port);
            break;
    }

// All done at this point

exit:
    *offset = len;
    return len;
}


/**
 * IPV4 PROC DIR ENTRIES
 */

/**
 * Read /proc/dod/ipv4/icmp
 */
ssize_t proc_read_ipv4_icmp(struct file *file, char *userbuf, size_t len, loff_t *offset) {
    len = proc_read_int(userbuf, len, offset, icmp_enabled);
    *offset = len;
    return len;
}

/**
 * Write /proc/dod/ipv4/icmp
 */
ssize_t proc_write_ipv4_icmp(struct file *file, const char *userbuf, size_t len, loff_t *offset) {
    int tmp;

    len = proc_write_int(userbuf, len, offset, &tmp, valid_num);
    icmp_enabled = (bool)tmp;
    *offset = len;
    return len;
}

/**
 * Read /proc/dod/ipv4/udp
 */
ssize_t proc_read_ipv4_udp(struct file *file, char *userbuf, size_t len, loff_t *offset) {
   len = proc_read_int(userbuf, len, offset, udp_enabled);
   *offset = len;
   return len;
}

/**
 * Write /proc/dod/ipv4/udp
 */
ssize_t proc_write_ipv4_udp(struct file *file, const char *userbuf, size_t len, loff_t *offset) {
    unsigned int tmp;

    len = proc_write_int(userbuf, len, offset, &tmp, valid_num);
    udp_enabled = (bool)tmp;
    *offset = len;
    return len;
}

/**
 * Read /proc/dod/ipv4/tcp
 */
ssize_t proc_read_ipv4_tcp(struct file *file, char *userbuf, size_t len, loff_t *offset) {
   len =  proc_read_int(userbuf, len, offset, tcp_enabled);
   *offset = len;
   return len;
}

/**
 * Write /proc/dod/ipv4/tcp
 */
ssize_t proc_write_ipv4_tcp(struct file *file, const char *userbuf, size_t len, loff_t *offset) {
    unsigned int tmp;

    len = proc_write_int(userbuf, len, offset, &tmp, valid_num);
    tcp_enabled = (bool)tmp;
    *offset = len;

    return len;
}

/**
 * Generic read operation
 */
ssize_t proc_read_char(char* buf, size_t size, loff_t* offset, char *src) {
    char linebuf[PROCFS_LINEBUF_SIZE];
    size_t len;
 
    // We're not doing chunk style reading
    if (*offset > 0) return 0;
 
    // Prepare our output string
    sprintf(linebuf, "%s\n", src);
 
    len = min(size, strlen(linebuf));
 
    if (copy_to_user(buf, linebuf, len) != 0) {
#ifdef DOD_DEBUG
        printk(KERN_ERR "An error occured while reading");
#endif
        return 0;
    }
 
    return len;
}


/**
 * Generic write operation for char datatype
 */
ssize_t proc_write_char(const char *buf, size_t size, loff_t *offset, char *dest, char *valid_charset) {
    char linebuf[SETTING_BUF_SIZE] = {0};
    size_t len;

    if (*offset > 0) goto no_write;
    len = min(size, sizeof(linebuf) - 1);

    if (copy_from_user(linebuf, buf, len) != 0) {
#ifdef DOD_DEBUG
        printk(KERN_ERR "Error writing to procfs");
#endif
        return len;
    }

    // Remove newline chars
    rmnl(linebuf);

    // Validate the input
    if (!chkwl(valid_charset, linebuf)) goto exit;

    // Copy to destination
    strncpy(dest, linebuf, SETTING_BUF_SIZE);

exit:
    return len;
no_write:
    return 0;
}

/**
 * Generic read operation for int datatypes
 */
ssize_t proc_read_int(char* buf, size_t size, loff_t* offset, int src) {
    char linebuf[PROCFS_LINEBUF_SIZE];
    size_t len;

    // We're not doing chunk style reading
    if (*offset > 0) return 0;

    // Prepare our output string
    sprintf(linebuf, "%i\n", src);

    len = min(size, strlen(linebuf));

    if (copy_to_user(buf, linebuf, len) != 0) {
#ifdef DOD_DEBUG
        printk(KERN_ERR "An error occured while reading");
#endif
        return 0;
    }

    return len;
}

ssize_t proc_write_int(const char *buf, size_t size, loff_t *offset, int *dest, char *valid_charset) {
    char linebuf[SETTING_BUF_SIZE] = {0};
    size_t len;
    int result;
   
    if (*offset > 0) goto no_write;
    len = min(size, sizeof(linebuf) - 1);
   
    if (copy_from_user(linebuf, buf, len) != 0) {
#ifdef DOD_DEBUG
        printk(KERN_ERR "Error writing to procfs");
#endif
        goto exit;
    }
 
    // Remove newline chars
    rmnl(linebuf);
   
    // Validate the input
    if (!chkwl(valid_charset, linebuf)) goto exit;
  
    // Copy to destination
    if ((result = kstrtoint(linebuf, 10, dest)) < 0) {
        switch(result) {
            case -ERANGE:
#ifdef DOD_DEBUG
                printk(KERN_ERR "Out of range");
#endif
                goto exit;
            case -EINVAL:
#ifdef DOD_DEBUG
                printk(KERN_ERR "Parsing error");
#endif
                goto exit;
        }
    }

exit:
    return len; 
no_write:
    return 0;
}

/**
 * Create the procFS entries
 */
void init_proc_entries(void) {
    // Create parent directory
    proc_ent_dod    = proc_mkdir("dod", NULL);
    proc_ent_ipv4   = proc_mkdir("ipv4", proc_ent_dod);
    proc_ent_ports  = proc_mkdir("ports", proc_ent_dod);

    proc_ent_secret = proc_create("secret", 0600, proc_ent_dod, &proc_secret_fops);
    proc_ent_ipv4_authorized = proc_create("authorized", 0600, proc_ent_ipv4, &proc_ipv4_authorized_fops);

    proc_ent_ports_visible = proc_create("visible", 0600, proc_ent_ports, &proc_ports_visible_fops);
    proc_ent_ports_invisible = proc_create("invisible", 0600, proc_ent_ports, &proc_ports_invisible_fops);

    proc_ent_ipv4_icmp = proc_create("icmp", 0600, proc_ent_ipv4, &proc_ipv4_icmp_fops);
    proc_ent_ipv4_udp = proc_create("udp", 0600, proc_ent_ipv4, &proc_ipv4_udp_fops);
    proc_ent_ipv4_tcp = proc_create("tcp", 0600, proc_ent_ipv4, &proc_ipv4_tcp_fops);

}

/**
 * Removes the procFS entries
 */
void deinit_proc_entries(void) {
    proc_remove(proc_ent_ipv4_icmp);
    proc_remove(proc_ent_ipv4_udp);
    proc_remove(proc_ent_ipv4_tcp);
    proc_remove(proc_ent_ports_visible);
    proc_remove(proc_ent_ports_invisible);
    proc_remove(proc_ent_ipv4_authorized);
    proc_remove(proc_ent_secret);
    proc_remove(proc_ent_ports);
    proc_remove(proc_ent_ipv4);
    proc_remove(proc_ent_dod);
}

void init_queues(void) {
    authips = init_queue();
    visible_ports = init_queue();
    invisible_ports = init_queue();
}

void deinit_queues(void) {
    deinit_queue(&authips);
    deinit_queue(&visible_ports);
    deinit_queue(&invisible_ports);
}



/**
 * This function is called by the kernel upon insmod. It gets registered at the bottom of the file
 */
int __init dod_init(void) {
    printk(KERN_INFO "Doors of Durin active\n");
    printk(KERN_WARNING "DOD: The shared secret has the default value and needs to be changed!");
    init_proc_entries();
    init_queues();
    register_ipv4_hook();
    return 0; // Do this, or the kernel will bitch about suspicious activity, loading it anyway and then crashing.
}

/**
 * This functio is called upon exit (rmmod). Registration down below
 */
void __exit dod_exit(void)
{
    unregister_ipv4_hook();
    deinit_queues();
    deinit_proc_entries();

    printk(KERN_INFO "Doors of Durin inactive\n");
}



/**
 * STRING FUNCTIONS
 */

/**
 * chkwl() - Check whitelist
 * This function checks if all character in a string
 * are within the set of whitelisted characters
 */
bool chkwl(char *wl, char *str) {
    int i;

    for(i = 0; i < strlen(str); i++) {
        if (strchr(wl, str[i]) == NULL) return false;
    }

    return true;
}

/**
 * rmnl() - Remove Newline
 * Replaces the first character of the sequence \r\n with a newline
 */
void rmnl(char *buf) {
    int i;
    char nlchrs[] = {10,13};

    for(i = 0; i < strlen(buf) ; i++) {
        if (strchr(nlchrs, buf[i]) > 0) {
            buf[i] = 0;
            return;
        }
    } 
}


/**
 * Checks if the supplied string is a valid IPv4 address
 */
bool isvalidIPv4(const char *s) {
    char tail[16];
    unsigned int d[4];
    int len, c, i;

    len = strlen(s);

    if (len < 7 || len > 15)
        return false;

    tail[0] = 0;

    c = sscanf(s, "%3u.%3u.%3u.%3u%s", &d[0], &d[1], &d[2], &d[3], tail);

    if (c != 4 || tail[0])
        return false;

    for (i = 0; i < 4; i++)
        if (d[i] > 255)
            return false;

    return true;
}




/**
 * SET MODULE HOOKS
 */
MODULE_LICENSE("GPL");
module_init(dod_init);
module_exit(dod_exit);




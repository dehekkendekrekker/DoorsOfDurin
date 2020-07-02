#ifndef _DOD_CRYPTO_H
#define _DOD_CRYPTO_H

#include <linux/crypto.h>
#include <crypto/hash.h>


int sha256sum(char *, int, char*);
int md5sum(char *, int, char*);


#endif

#ifndef _ALGO_H
#define _ALGO_H

#include <linux/types.h>


/**
 * Prototype of QUEUE implementation
 */

typedef struct qlink {
    void *pitem;
    struct qlink *pnext;
    struct qlink *pprev;
} qlink;

typedef struct queue {
    qlink *pcur;
    qlink *pstart;
    qlink *pend;
    int cnt;
} queue;



qlink *create_qlink(void *);

queue init_queue(void);
void deinit_queue(queue *);
qlink *queue_pushi(queue *, void*);
void *queue_popi(queue *);
void queue_rewind(queue *);
qlink *queue_nexti(queue *);
void queue_unlink(queue *, qlink *);

#endif


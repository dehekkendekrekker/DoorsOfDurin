#include <linux/slab.h>
#include "algo.h"


/**************************************
 * QUEUE IMPLEMENTATION (DOUBLY LINKED LIST)
 *************************************/

queue init_queue() {
    queue q;
    q.pcur = NULL;
    q.pstart = NULL;
    q.pend = NULL;
    q.cnt= 0;

    return q;
}

void deinit_queue(queue *pq) {
    void *ptr;

       // Empty the sequence queue
    while ((ptr = queue_popi(pq)) != NULL) {
        kfree(ptr);
    }
}

/**
 * Creates a new qlink
 */
qlink *create_qlink(void *pitem) {
    qlink *pqlink ;

    pqlink = kcalloc(1, sizeof(qlink), GFP_KERNEL);
    pqlink->pitem = pitem;
    pqlink->pnext = NULL;
    pqlink->pprev = NULL;

    return pqlink;
}

/**
 * Appends a qlink at the end of the queue
 */
qlink *queue_pushi(queue *pqueue, void *pitem) {
    qlink *pqlink, *pnewqlink;     

    // Create a new qlink
    pnewqlink = create_qlink(pitem);

    // If the list is empty, make the new link the start of the queue as well
    if (pqueue->cnt == 0) {
        pqueue->pstart = pnewqlink;
        pqueue->pend = pnewqlink;

        goto inc_q_cnt;
    }

    // Get the last link
    pqlink = pqueue->pend;

    // Stick the new link after the last link
    pqlink->pnext = pnewqlink;
    pnewqlink->pprev = pqlink;

    // Make the new link, the last link
    pqueue->pend = pqlink->pnext;

    // If the list is empty, make the new link the start of the queue as well
    if (pqueue->cnt == 0) {
        pqueue->pstart = pnewqlink;
        pqueue->pcur = pqueue->pstart;
    }

inc_q_cnt:
    pqueue->cnt++;
    return pnewqlink;
}

/**
 * Pops the pointer to the item on the list off the first link.
 * The algorithm will take care of freeing used blocks for its own system
 * The caller needs to take care of freeing the item itself
 */
void *queue_popi(queue *pqueue) {
    void *pitem;
    qlink *pqlink;

    // In case there are no links in the queue
    if (pqueue->cnt == 0) return NULL;

    // Get the first link of the queue, and put it on the stack
    pqlink = pqueue->pstart;

    // Make the next link the first link
    pqueue->pstart = pqlink->pnext;

    // Get the pointer to the item
    pitem = pqlink->pitem;

    // Free the link on the stack
    kfree(pqlink);

    // Decrease cnt;
    pqueue->cnt--;
    // Return the pointer to the item
    return pitem;
}

/**
 * Returns the next item in the queue
 */
qlink *queue_nexti(queue *pqueue){
    qlink *pcur;

    pcur = pqueue->pcur;

    // This occurs when we've reached the end of the list
    if (pcur == NULL) return NULL;

    pqueue->pcur = pcur->pnext; // Set the internal pointer to the next link

    return pcur;
}

/**
 * Sets the internal pointer to the first link in the queue
 */
void queue_rewind(queue *pqueue) {
    pqueue->pcur = pqueue->pstart;
}

/**
 * Removes a link from the queue.
 * The caller has the responsibility to free to void pointer pitem
 */
void queue_unlink(queue *pqueue, qlink *pqlink) {
    // Failsafe
    if (pqlink == NULL) return;


    // There is only one item in the list that will be unlinked
    //
    if (pqlink == pqueue->pstart && pqlink == pqueue->pend) {
        pqueue->pstart = NULL;
        pqueue->pend   = NULL;
        pqueue->pcur   = NULL;

        goto queue_unlink_free; 
    }

    // If the to be deleted qlink is at the end
    if (pqlink == pqueue->pend) {
        // Make previous link the end of the chain.
        pqueue->pend = pqlink->pprev;

        // Erase the reference to the to be deleted qlink
        pqlink->pprev->pnext = NULL;

        // If the to be deleted qlink is the current, make the previous the current
        if (pqueue->pcur == pqlink)
            pqueue->pcur = pqlink->pprev;

        goto queue_unlink_free;
    }

    // If the to be deleted link is at the start
    if (pqlink == pqueue->pstart) {
        // Make the next link the start of the chain
        pqueue->pstart = pqlink->pnext;

        // Erase the reference to the deleted link
        pqlink->pnext->pprev = NULL;

        // If the to be deleted qlink is the current, make the next the current
        if (pqueue->pcur == pqlink)
            pqueue->pcur = pqlink->pnext;

        goto queue_unlink_free;
    }

    // The link is somewhere in the middle of the chain at this point
    pqlink->pnext->pprev = pqlink->pprev;
    pqlink->pprev->pnext = pqlink->pnext;
    if (pqueue->pcur == pqlink)
        pqueue->pcur = pqlink->pnext;


    
queue_unlink_free:
    // Free the memory of the qlink
    kfree(pqlink);
    pqueue->cnt--;

    return;
}




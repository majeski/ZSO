#ifndef _V2D_IDS_QUEUE_H
#define _V2D_IDS_QUEUE_H

typedef struct {
    int id;
    int ready;
    struct list_head lhead;
} ids_queue_elem;

typedef struct {
    int last_woken;
    int cur;
    wait_queue_head_t wait_q;
    struct list_head ids_list;
    spinlock_t spinlock;
} ids_queue;

static inline void init_ids_queue(ids_queue *q)
{
    q->last_woken = q->cur = 0;
    init_waitqueue_head(&q->wait_q);
    INIT_LIST_HEAD(&q->ids_list);
    spin_lock_init(&q->spinlock);
}

static inline int
ready_to_wakeup(ids_queue_elem *elem, int last_woken, int current_ready_id)
{
    if (last_woken <= current_ready_id) {
        return last_woken <= elem->id && elem->id <= current_ready_id;
    }
    return elem->id >= last_woken || elem->id <= current_ready_id;
}

#endif

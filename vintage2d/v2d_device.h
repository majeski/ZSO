#ifndef V2D_DEVICE
#define V2D_DEVICE

#include "v2d_ids_queue.h"

#define V2D_BUF_SIZE 2048

typedef struct {
    u32 *kptr;
    dma_addr_t dptr;
    int head; /* protected by lock */
    int tail;
    struct mutex lock;
} v2d_buffer;

typedef struct {
    struct cdev cdev;
    struct pci_dev *pdev;
    struct device *dev;
    int minor;
    struct dma_pool *dma_pool;
    
    v2d_buffer buffer;
    wait_queue_head_t buf_queue;

    void __iomem *bar0;

    ids_queue fsync_queue; 
    struct tasklet_struct bh_tasklet;
} v2d_device;

static inline int init_buffer(struct pci_dev *pdev, v2d_buffer *buf)
{
    buf->kptr = dma_zalloc_coherent(
        &pdev->dev, V2D_BUF_SIZE << 2, &buf->dptr, GFP_KERNEL);
    if (unlikely(!buf->kptr || !buf->dptr)) {
        buf->kptr = NULL;
        dev_err(&pdev->dev, "dma_zalloc_coherent failed\n");
        return -ENOMEM;
    }

    buf->head = buf->tail = 0;
    buf->kptr[V2D_BUF_SIZE - 1] = buf->dptr | VINTAGE2D_CMD_KIND_JUMP;
    mutex_init(&buf->lock);
    return 0;
}

static inline void destroy_buffer(struct pci_dev *pdev, v2d_buffer *buf)
{
    dma_free_coherent(&pdev->dev, V2D_BUF_SIZE << 2, buf->kptr, buf->dptr);
    mutex_destroy(&buf->lock);
}

static inline int32_t buf_space(v2d_buffer *buf)
{
    int head = buf->head;
    int tail = buf->tail;
    rmb();

    if (head >= tail) {
        return V2D_BUF_SIZE - 2 - head + tail;
    }
    return tail - head - 1;
}

static inline void add_cmd(v2d_buffer *buf, u32 cmd)
{
    buf->kptr[buf->head] = cmd;
    buf->head = (buf->head + 1) % (V2D_BUF_SIZE - 1);
}

static inline u32 *get_last_cmd(v2d_buffer *buf)
{
    if (unlikely(!buf->head)) {
        return buf->kptr + V2D_BUF_SIZE - 2;
    } 
    return buf->kptr + buf->head - 1;
}

/* save write_ptr to register */
static inline void save_buf_head(v2d_device *dev)
{
    v2d_buffer *buf = &dev->buffer;
    iowrite32(buf->dptr + (buf->head << 2), dev->bar0 + VINTAGE2D_CMD_WRITE_PTR);
}

/* load read_ptr from register */
static inline void load_buf_tail(v2d_device *dev)
{
    v2d_buffer *buf = &dev->buffer;
    buf->tail = (ioread32(dev->bar0 + VINTAGE2D_CMD_READ_PTR) - buf->dptr) >> 2;
}

#endif

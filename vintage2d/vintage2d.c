#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/spinlock.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>

#include "v2d_ioctl.h"
#include "vintage2d.h"

#include "v2d_context.h"
#include "v2d_device.h"
#include "v2d_ids_queue.h"

MODULE_LICENSE("GPL");

#define V2D_COUNTER_MAX 0x01000000
#define V2D_RESET_ALL \
    (VINTAGE2D_RESET_TLB | VINTAGE2D_RESET_FIFO | VINTAGE2D_RESET_DRAW)

#define DEV_COUNT 256
#define MIN_DIM 1
#define MAX_DIM 2048

static struct class *v2d_class;
static dev_t dev_base;
static DEFINE_IDR(v2d_idr);

static const struct pci_device_id v2d_id_table[2] = {
    {PCI_DEVICE(VINTAGE2D_VENDOR_ID, VINTAGE2D_DEVICE_ID)}
};
static int v2d_probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void v2d_remove(struct pci_dev *pdev);

static struct pci_driver v2d_driver = {
    name: "vintage2d",
    id_table: v2d_id_table,
    probe: v2d_probe,
    remove: v2d_remove,
};

/* module init & exit */

static int __init v2d_init_module(void)
{
    int err;

    err = alloc_chrdev_region(&dev_base, 0, DEV_COUNT, "v2d");
    if (IS_ERR_VALUE(err)) {
        pr_err("alloc_chrdev_region failed with %d\n", err);
        return err;
    }

    v2d_class = class_create(THIS_MODULE, "v2d");
    if (IS_ERR(v2d_class)) {
        err = PTR_ERR(v2d_class);
        pr_err("class_create failed with %d\n", err);
        goto err_chrdev_register;
    }

    err = pci_register_driver(&v2d_driver);
    if (IS_ERR_VALUE(err)) {
        pr_err("pci_register_driver failed with %d\n", err);
        goto err_class;
    }

    return 0;

err_class:
    idr_destroy(&v2d_idr);
    class_destroy(v2d_class);
err_chrdev_register:
    unregister_chrdev_region(dev_base, DEV_COUNT);
    return err;
}

static void __exit v2d_cleanup_module(void)
{
    pci_unregister_driver(&v2d_driver);
    idr_destroy(&v2d_idr);
    class_destroy(v2d_class);
    unregister_chrdev_region(dev_base, DEV_COUNT);
}

module_init(v2d_init_module);
module_exit(v2d_cleanup_module);

static ssize_t 
v2d_write(struct file *file, const char __user *in, size_t size, loff_t *d);
static int v2d_fsync(struct file *file, loff_t a, loff_t b, int datasync);
static long v2d_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int v2d_mmap(struct file *file, struct vm_area_struct *vma);
static int v2d_open(struct inode *inode, struct file *file);
static int v2d_release(struct inode *inode, struct file *file);

static struct file_operations v2d_fops = {
    owner: THIS_MODULE,
    write: v2d_write,
    fsync: v2d_fsync,
    unlocked_ioctl: v2d_ioctl,
    mmap: v2d_mmap,
    open: v2d_open,
    release: v2d_release,
};

static DEFINE_SPINLOCK(idr_lock);

static int v2d_prepare_device(struct pci_dev *pdev, v2d_device *data);
static void v2d_cleanup_device(struct pci_dev *pdev, v2d_device *data);
static irqreturn_t v2d_handler(int irq, void *data);
static void v2d_tasklet(unsigned long d);

static int v2d_probe(struct pci_dev *pdev, const struct pci_device_id *id) 
{
    int err;
    v2d_device *dev;

    dev = kmalloc(sizeof(v2d_device), GFP_KERNEL);
    if (unlikely(!dev)) {
        pr_err("kmalloc failed\n");
        return -ENOMEM;
    }

    idr_preload(GFP_KERNEL);
    spin_lock(&idr_lock);
    dev->minor = idr_alloc(&v2d_idr, dev, 0, DEV_COUNT, GFP_NOWAIT);
    spin_unlock(&idr_lock);
    idr_preload_end();

    if (IS_ERR_VALUE(dev->minor)) {
        err = dev->minor;
        pr_err("idr_alloc failed with %d\n", err);
        goto err_kmalloc;
    }

    cdev_init(&dev->cdev, &v2d_fops);
    dev->pdev = pdev;
    pci_set_drvdata(pdev, dev);

    err = cdev_add(&dev->cdev, dev_base + dev->minor, 1);
    if (IS_ERR_VALUE(err)) {
        pr_err("cdev_add failed with %d\n", err);
        goto err_idr;
    }

    dev->dev = device_create(
        v2d_class, NULL, dev_base + dev->minor, NULL, "v2d%d", dev->minor);
    if (IS_ERR(dev->dev)) {
        err = PTR_ERR(dev->dev);
        pr_err("device_create failed with %d\n", err);
        goto err_cdev_add;
    }

    err = v2d_prepare_device(pdev, dev);
    if (IS_ERR_VALUE(err)) {
        goto err_dev_create;
    }

    dev->dma_pool = dma_pool_create("vintage2d", &pdev->dev,
        VINTAGE2D_PAGE_SIZE, VINTAGE2D_PAGE_SIZE, 0);
    if (IS_ERR(dev->dma_pool)) {
        err = PTR_ERR(dev->dma_pool);
        pr_err("dma_pool_create failed with %d\n", err);
        goto err_prep_dev;
    }

    err = init_buffer(pdev, &dev->buffer);
    if (IS_ERR_VALUE(err)) {
        goto err_dma_pool;
    }
    init_waitqueue_head(&dev->buf_queue);

    init_ids_queue(&dev->fsync_queue);
    tasklet_init(&dev->bh_tasklet, v2d_tasklet, (unsigned long)dev);

    iowrite32(dev->buffer.dptr, dev->bar0 + VINTAGE2D_CMD_READ_PTR);
    iowrite32(dev->buffer.dptr, dev->bar0 + VINTAGE2D_CMD_WRITE_PTR);
    iowrite32(VINTAGE2D_INTR_NOTIFY, dev->bar0 + VINTAGE2D_INTR_ENABLE);
    iowrite32(VINTAGE2D_ENABLE_DRAW | VINTAGE2D_ENABLE_FETCH_CMD,
        dev->bar0 + VINTAGE2D_ENABLE); 

    wmb();
    add_cmd(&dev->buffer, VINTAGE2D_CMD_COUNTER(0, 0));

    return 0;

err_dma_pool:
    dma_pool_destroy(dev->dma_pool);
err_prep_dev:
    v2d_cleanup_device(pdev, dev);
err_dev_create:
    device_destroy(v2d_class, dev_base + dev->minor);
err_cdev_add:
    cdev_del(&dev->cdev);
err_idr:
    spin_lock(&idr_lock);
    idr_remove(&v2d_idr, dev->minor);
    spin_unlock(&idr_lock);
err_kmalloc:
    kfree(dev);
    return err;
}

static void v2d_remove(struct pci_dev *pdev) {
    v2d_device *dev = pci_get_drvdata(pdev);

    spin_lock(&idr_lock);
    idr_remove(&v2d_idr, dev->minor);
    spin_unlock(&idr_lock);

    cdev_del(&dev->cdev);
    device_destroy(v2d_class, dev_base + dev->minor);

    destroy_buffer(pdev, &dev->buffer);
    dma_pool_destroy(dev->dma_pool);
    v2d_cleanup_device(pdev, dev);
    kfree(dev);
}

static irqreturn_t v2d_handler(int irq, void *data)
{
    v2d_device *dev = data;
    u32 intr;

    intr = ioread32(dev->bar0 + VINTAGE2D_INTR);
    if (!intr) {
        return IRQ_NONE;
    }
    iowrite32(intr, dev->bar0 + VINTAGE2D_INTR);

    tasklet_schedule(&dev->bh_tasklet);
    return IRQ_HANDLED;
}

static void v2d_tasklet(unsigned long d)
{
    u32 cur_counter;
    int wakeup_fsyncs = 0;
    v2d_device *dev = (v2d_device *) d;
    ids_queue *fsync_q = &dev->fsync_queue;
    ids_queue_elem *entry, *tmp;

    spin_lock(&fsync_q->spinlock);
    cur_counter = ioread32(dev->bar0 + VINTAGE2D_COUNTER);
    if (cur_counter != fsync_q->last_woken) {
        list_for_each_entry_safe(entry, tmp, &fsync_q->ids_list, lhead) {
            if (!ready_to_wakeup(entry, fsync_q->last_woken, cur_counter)) {
                break;
            }
            fsync_q->last_woken = entry->id;
            entry->ready = 1;
            wakeup_fsyncs = 1;
            list_del(&entry->lhead);
        }
    }
    load_buf_tail(dev);
    spin_unlock(&fsync_q->spinlock);

    if (wakeup_fsyncs) {
        wake_up(&dev->fsync_queue.wait_q);
    }
    wake_up(&dev->buf_queue);
}

static int v2d_prepare_device(struct pci_dev *pdev, v2d_device *data)
{
    int err;
    int intr;

    err = pci_enable_device(pdev);
    if (IS_ERR_VALUE(err)) {
        pr_err("pci_enable_device failed with %d\n", err);
        return err;
    }

    err = pci_request_regions(pdev, "v2d");
    if (IS_ERR_VALUE(err)) {
        pr_err("pci_request_regions failed with %d\n", err);
        goto err_enable;
    }
    
    data->bar0 = pci_iomap(pdev, 0, 0);
    if (!data->bar0) {
        pr_err("pci_iomap failed\n");
        err = -EIO;
        goto err_regions;
    }

    pci_set_master(pdev);
    err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if (IS_ERR_VALUE(err)) {
        pr_err("dma_set_mask_and_coherent failed with %d\n", err);
        goto err_set_master;
    }
    
    iowrite32(V2D_RESET_ALL, data->bar0 + VINTAGE2D_RESET);
    intr = ioread32(data->bar0 + VINTAGE2D_INTR);
    iowrite32(intr, data->bar0 + VINTAGE2D_INTR);

    err = request_irq(pdev->irq, v2d_handler, IRQF_SHARED, "v2d", data);
    if (IS_ERR_VALUE(err)) {
        pr_err("request_irq failed with %d\n", err);
        goto err_set_master;     
    }

    return 0;

err_set_master:
    pci_clear_master(pdev);
    pci_iounmap(pdev, data->bar0);
err_regions:
    pci_release_regions(pdev);
err_enable:
    pci_disable_device(pdev);
    return err;
}

static void
v2d_cleanup_device(struct pci_dev *pdev, v2d_device *data)
{
    iowrite32(0, data->bar0 + VINTAGE2D_ENABLE);
    iowrite32(0, data->bar0 + VINTAGE2D_INTR_ENABLE);
    free_irq(pdev->irq, data);
    iowrite32(V2D_RESET_ALL, data->bar0 + VINTAGE2D_RESET);
    pci_clear_master(pdev);
    pci_iounmap(pdev, data->bar0);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
}

/* file operations */

static void delete_page_table(v2d_context *context);

/* returns with obtained dev->buffer.lock or returns error caused by signal */
static int wait_for_space_interruptible(v2d_device *dev, int space);
static void wait_for_space(v2d_device *dev, int space);

static void add_fsync_id(ids_queue *q, ids_queue_elem *elem);
static void del_fsync_id(ids_queue *q, ids_queue_elem *elem);

static int v2d_open(struct inode *inode, struct file *file)
{
    v2d_context *context;
    v2d_device *dev;

    spin_lock(&idr_lock);
    dev = idr_find(&v2d_idr, MINOR(inode->i_rdev));
    spin_unlock(&idr_lock);
    
    if (dev == NULL) {
        BUG_ON(dev == NULL);
        return -EIO;
    }

    context = kmalloc(sizeof(v2d_context), GFP_KERNEL);
    if (unlikely(!context)) {
        pr_err("kmalloc failed\n");
        return -ENOMEM;
    }

    init_context(context);
    context->v2d_dev = dev;
    file->private_data = context;
    return 0;
}

static long v2d_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int err;
    int i;
    u32 size;
    dma_addr_t dma_ptr;
    v2d_context *context = file->private_data;
    v2d_device *dev = context->v2d_dev;

    err = mutex_lock_interruptible(&context->dims_lock);
    if (unlikely(err)) {
        return err;
    }

    if (unlikely(cmd != V2D_IOCTL_SET_DIMENSIONS)) {
        err = -ENOTTY;
        goto end;
    }

    /* check if dimensions are already set */
    if (unlikely(context->pages_vm)) {
        err = -EINVAL;
        goto end;
    }

    err = copy_from_user(&context->dims, (void *)arg, sizeof(context->dims));
    if (unlikely(err)) {
        err = -EFAULT;
        goto end;
    }
    if (unlikely(
        context->dims.width < MIN_DIM || context->dims.width > MAX_DIM ||
        context->dims.height < MIN_DIM || context->dims.height > MAX_DIM)) {
        err = -EINVAL;
        goto end;
    }

    context->pages_vm = kmalloc(VINTAGE2D_PAGE_SIZE, GFP_KERNEL);
    if (unlikely(!context->pages_vm)) {
        err = -ENOMEM;
        goto end;
    }

    /* alloc page table */
    context->pages_dma = dma_pool_alloc(dev->dma_pool, GFP_KERNEL, &context->pt_dma);
    if (unlikely(!context->pages_dma || !context->pt_dma)) {
        pr_err("dma_pool_alloc failed\n");
        context->pages_dma = NULL;
        err = -ENOMEM;
        goto err_zalloc;
    }
    memset(context->pages_dma, 0, VINTAGE2D_PAGE_SIZE);

    /* alloc each page */
    size = (u32)context->dims.width * context->dims.height;
    context->page_count = 
        roundup(size, VINTAGE2D_PAGE_SIZE) / VINTAGE2D_PAGE_SIZE;
    for (i = 0; i < context->page_count; i++) {
        context->pages_vm[i] = dma_pool_alloc(dev->dma_pool, GFP_KERNEL, &dma_ptr);
        if (unlikely(!context->pages_vm[i] || !dma_ptr)) {
            pr_err("dma_pool_alloc failed\n");
            context->pages_vm[i] = NULL;
            err = -ENOMEM;
            goto err_zalloc;
        }
        memset(context->pages_vm[i], 0, VINTAGE2D_PAGE_SIZE);
        context->pages_dma[i] = dma_ptr | VINTAGE2D_PTE_VALID;
    }

    err = 0;
    set_canvas_cmds(context);
    iowrite32(VINTAGE2D_RESET_TLB, context->v2d_dev->bar0 + VINTAGE2D_RESET);

    wmb();
    context->pt_ready = 1;
    goto end;

err_zalloc:
    delete_page_table(context);
end:
    mutex_unlock(&context->dims_lock);
    return err;
}

static int v2d_release(struct inode *inode, struct file *file)
{
    v2d_context *context = file->private_data;
    v2d_device *dev = context->v2d_dev;
    ids_queue_elem list_elem;

    wait_for_space(dev, 1);
    add_fsync_id(&dev->fsync_queue, &list_elem);
    add_cmd(&dev->buffer, VINTAGE2D_CMD_COUNTER(list_elem.id, 1));
    save_buf_head(dev);
    mutex_unlock(&dev->buffer.lock);

    wait_event(dev->fsync_queue.wait_q, list_elem.ready);

    delete_page_table(context);
    kfree(context);
    return 0;
}

static void delete_page_table(v2d_context *context)
{
    int i;
    u32 dma_ptr;
    v2d_device *dev = context->v2d_dev;

    for (i = 0; i < context->page_count && context->pages_vm[i]; i++) {
        dma_ptr = context->pages_dma[i] & 0xFFFFF000;
        dma_pool_free(dev->dma_pool, context->pages_vm[i], dma_ptr);
    }

    if (context->pages_dma) {
        dma_pool_free(dev->dma_pool, context->pages_dma, context->pt_dma);
    }
    kfree(context->pages_vm);
    context->page_count = 0;
    context->pages_dma = NULL;
    context->pages_vm = NULL;
}

static int v2d_mmap(struct file *file, struct vm_area_struct *vma)
{
    int i;
    int err;
    unsigned long cur_addr;
    struct page *page;
    v2d_context *context = file->private_data;
    
    if (unlikely(!context->pt_ready)) {
        return -EINVAL;
    }
 
    if (unlikely(context->page_count < vma->vm_pgoff + 
        (vma->vm_end - vma->vm_start) / VINTAGE2D_PAGE_SIZE)) {
        return -EINVAL;
    }

    cur_addr = vma->vm_start;
    for (i = vma->vm_pgoff; cur_addr < vma->vm_end; i++, cur_addr += VINTAGE2D_PAGE_SIZE) {
        page = virt_to_page(context->pages_vm[i]);
        err = vm_insert_page(vma, cur_addr, page);
        if (IS_ERR_VALUE(err)) {
            return err;
        }
    }
    
    return 0;
}

static ssize_t 
v2d_write(struct file *file, const char __user *in, size_t size, loff_t *d)
{
    int err = 0;
    int read = 0;
    u32 user_cmd;
    u32 dev_cmd;
    v2d_context *context = file->private_data;
    v2d_device *dev = context->v2d_dev;
    v2d_buffer *buf = &dev->buffer;
    u32 old_buf_head;
    u32 *last_cmd = NULL;
 
    if (unlikely(!context->pt_ready || size < 4)) {
        return -EINVAL;
    }

    err = wait_for_space_interruptible(dev, 5);
    if (IS_ERR_VALUE(err)) {
        return err;
    }

    old_buf_head = buf->head;
    add_cmd(buf, context->cmd_setup.canvas_pt);
    add_cmd(buf, context->cmd_setup.canvas_dims);
    
    /* until there is enough space in buffer & 
     * there is potentially correct command */
    while (!err && read + 4 <= size && buf_space(buf) >= 3) {
        err = get_user(user_cmd, (u32 *)in);
        in += 4;
        if (IS_ERR_VALUE(err)) {
            break;
        }

        switch (V2D_CMD_TYPE(user_cmd)) {
            case V2D_CMD_TYPE_SRC_POS:  
                err = set_src_pos(context, user_cmd);
                break;
            case V2D_CMD_TYPE_DST_POS:
                err = set_dst_pos(context, user_cmd);
                break;
            case V2D_CMD_TYPE_FILL_COLOR:
                err = set_fill_color(context, user_cmd);
                break;
            case V2D_CMD_TYPE_DO_BLIT:
                err = parse_blit(context, user_cmd, &dev_cmd);
                if (likely(!err)) {
                    add_cmd(buf, context->cmd_setup.src_pos);
                    add_cmd(buf, context->cmd_setup.dst_pos);
                    add_cmd(buf, dev_cmd);
                    last_cmd = get_last_cmd(buf); 
                    clear_setup(context);
                }
                break;
            case V2D_CMD_TYPE_DO_FILL:
                err = parse_fill(context, user_cmd, &dev_cmd);
                if (likely(!err)) {
                    add_cmd(buf, context->cmd_setup.fill_color);
                    add_cmd(buf, context->cmd_setup.dst_pos); 
                    add_cmd(buf, dev_cmd);
                    last_cmd = get_last_cmd(buf); 
                    clear_setup(context);
                }
                break;
            default:
                err = -EINVAL;
                break;
        }

        if (likely(!err)) {
            read += 4;
        }
    }

    /* error only if no data was read */
    if (unlikely(!read)) {
        BUG_ON(!IS_ERR_VALUE(err));
        read = err;
        buf->head = old_buf_head;
    } else if (last_cmd) {
        *last_cmd |= VINTAGE2D_CMD_KIND_CMD_NOTIFY;
        save_buf_head(dev);
    } else {
        buf->head = old_buf_head;
    }
    
    mutex_unlock(&buf->lock);
    return read;
}


static int v2d_fsync(struct file *file, loff_t a, loff_t b, int datasync)
{
    int err;
    v2d_context *context = file->private_data;
    v2d_device *dev = context->v2d_dev;
    ids_queue_elem list_elem;

    if (unlikely(!context->pt_ready)) {
        return -EINVAL;
    }

    err = wait_for_space_interruptible(dev, 1);
    if (IS_ERR_VALUE(err)) {
        return err;
    }

    /* obtain id & write counter command */
    add_fsync_id(&dev->fsync_queue, &list_elem);
    add_cmd(&dev->buffer, VINTAGE2D_CMD_COUNTER(list_elem.id, 1));
    save_buf_head(dev);
    mutex_unlock(&dev->buffer.lock);

    /* sleep on fsync queue */
    err = wait_event_interruptible(dev->fsync_queue.wait_q, list_elem.ready);
    if (IS_ERR_VALUE(err)) {
        del_fsync_id(&dev->fsync_queue, &list_elem);
    }

    return err;
}

static void add_fsync_id(ids_queue *q, ids_queue_elem *elem)
{
    spin_lock_irq(&q->spinlock);
    q->cur = (q->cur + 1) % V2D_COUNTER_MAX;
    elem->id = q->cur;
    elem->ready = 0;
    list_add_tail(&elem->lhead, &q->ids_list);
    spin_unlock_irq(&q->spinlock);
}

static void del_fsync_id(ids_queue *q, ids_queue_elem *elem)
{
    spin_lock_irq(&q->spinlock);
    if (!elem->ready) {
        list_del(&elem->lhead);
    }
    spin_unlock_irq(&q->spinlock);
}

static int wait_for_space_interruptible(v2d_device *dev, int space)
{
    int err;
    v2d_buffer *buf = &dev->buffer;

    mutex_lock(&buf->lock);
    while (buf_space(buf) < space) {
        mutex_unlock(&buf->lock);
        err = wait_event_interruptible(
            dev->buf_queue, buf_space(buf) >= space);
        if (IS_ERR_VALUE(err)) {
            return err;
        }
        mutex_lock(&buf->lock);
    }
    return 0;
}

static void wait_for_space(v2d_device *dev, int space)
{
    v2d_buffer *buf = &dev->buffer;

    mutex_lock(&buf->lock);
    while (buf_space(buf) < space) {
        mutex_unlock(&buf->lock);
        wait_event(dev->buf_queue, buf_space(buf) >= space);
        mutex_lock(&buf->lock);
    }
}

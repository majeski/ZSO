#ifndef _V2D_CONTEXT_H
#define _V2D_CONTEXT_H

#include "v2d_device.h"

typedef struct {
    u32 canvas_pt;
    u32 canvas_dims;
    int set;
    u32 dst_pos;
    u32 src_pos;
    u32 fill_color;
} v2d_cmd_setup;

#define SETUP_SRC_POS 1
#define SETUP_DST_POS 2
#define SETUP_FILL_COLOR 4

typedef struct {
    v2d_device *v2d_dev;

    void **pages_vm; /* kernel ptr to page table */
    u32 *pages_dma; /* device ptrs to pages */
    dma_addr_t pt_dma; /* device ptr to page table */
    int page_count;
    int pt_ready;
    
    struct v2d_ioctl_set_dimensions dims;
    struct mutex dims_lock;

    v2d_cmd_setup cmd_setup;
} v2d_context;

static inline void clear_setup(v2d_context *context)
{
    context->cmd_setup.set = 0;
}

static inline void init_context(v2d_context *context)
{
    context->pages_vm = NULL;
    context->pages_dma = NULL;
    context->page_count = 0;
    context->pt_ready = 0;
    mutex_init(&context->dims_lock); 
    clear_setup(context);
}

static inline void set_canvas_cmds(v2d_context *context)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    setup->canvas_pt = VINTAGE2D_CMD_CANVAS_PT(context->pt_dma, 0);
    setup->canvas_dims = 
        VINTAGE2D_CMD_CANVAS_DIMS(context->dims.width, context->dims.height, 0);
}

static inline int parse_blit(v2d_context *context, u32 user_cmd, u32 *dev_cmd)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    u32 src_x = VINTAGE2D_CMD_POS_X(setup->src_pos);
    u32 src_y = VINTAGE2D_CMD_POS_Y(setup->src_pos);
    u32 dst_x = VINTAGE2D_CMD_POS_X(setup->dst_pos);
    u32 dst_y = VINTAGE2D_CMD_POS_Y(setup->dst_pos);
    u32 width = V2D_CMD_WIDTH(user_cmd);
    u32 height = V2D_CMD_HEIGHT(user_cmd);

    if (unlikely(
        V2D_CMD_DO_BLIT(width, height) != user_cmd ||
        !(setup->set & SETUP_SRC_POS) || !(setup->set & SETUP_DST_POS) ||
        src_x + width > context->dims.width ||
        src_y + height > context->dims.height ||
        dst_x + width > context->dims.width ||
        dst_y + height > context->dims.height)) {
        return -EINVAL;
    }

    *dev_cmd = VINTAGE2D_CMD_DO_BLIT(width, height, 0);
    return 0;
}

static inline int parse_fill(v2d_context *context, u32 user_cmd, u32 *dev_cmd)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    u32 x = VINTAGE2D_CMD_POS_X(setup->dst_pos);
    u32 y = VINTAGE2D_CMD_POS_Y(setup->dst_pos);
    u32 width = V2D_CMD_WIDTH(user_cmd);
    u32 height = V2D_CMD_HEIGHT(user_cmd);

    if (unlikely(
        V2D_CMD_DO_FILL(width, height) != user_cmd ||
        !(setup->set & SETUP_FILL_COLOR) || !(setup->set & SETUP_DST_POS) ||
        x + width > context->dims.width || 
        y + height > context->dims.height)) {
        return -EINVAL;
    }
    
    *dev_cmd = VINTAGE2D_CMD_DO_FILL(width, height, 0);
    return 0;
}

static inline int set_src_pos(v2d_context *context, u32 user_cmd)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    u32 x = V2D_CMD_POS_X(user_cmd);
    u32 y = V2D_CMD_POS_Y(user_cmd);

    if (unlikely(
        V2D_CMD_SRC_POS(x, y) != user_cmd ||
        x >= context->dims.width || y >= context->dims.height)) {
        return -EINVAL;
    }

    setup->set |= SETUP_SRC_POS;
    setup->src_pos = VINTAGE2D_CMD_SRC_POS(x, y, 0); 
    return 0;
}

static inline int set_dst_pos(v2d_context *context, u32 user_cmd)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    u32 x = V2D_CMD_POS_X(user_cmd);
    u32 y = V2D_CMD_POS_Y(user_cmd);

    if (unlikely(
        V2D_CMD_DST_POS(x, y) != user_cmd ||
        x >= context->dims.width || y >= context->dims.height)) {
        return -EINVAL;
    }

    setup->set |= SETUP_DST_POS;
    setup->dst_pos = VINTAGE2D_CMD_DST_POS(x, y, 0); 
    return 0;
}

static inline int set_fill_color(v2d_context *context, u32 user_cmd)
{
    v2d_cmd_setup *setup = &context->cmd_setup;
    u32 color = V2D_CMD_COLOR(user_cmd);

    if (unlikely(
        V2D_CMD_FILL_COLOR(color) != user_cmd)) {
        return -EINVAL;
    }

    setup->set |= SETUP_FILL_COLOR;
    setup->fill_color = VINTAGE2D_CMD_FILL_COLOR(color, 0);
    return 0;
}

#endif

/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_RX_H_
#define UCT_IB_MLX5_RX_H_

#include "ib_mlx5.h"

typedef enum {
    UCT_IB_MLX5_SRQ_TOPO_LIST,
    UCT_IB_MLX5_SRQ_TOPO_CYCLIC,
    UCT_IB_MLX5_SRQ_TOPO_CYCLIC_EMULATED,
    UCT_IB_MLX5_SRQ_TOPO_LAST
} uct_ib_mlx5_srq_topo_t;


typedef struct {
    uct_ib_mlx5_srq_topo_t topo;
    int                    queue_len;
    int                    sge_num;
    size_t                 seg_size;
    int                    mp;
    int                    pdn;
} uct_ib_mlx5_srq_attr_t;


/* Shared receive queue */
typedef struct uct_ib_mlx5_srq {
    uct_ib_srq_t                       super;
    uct_ib_mlx5_obj_type_t             type;
    uint32_t                           srq_num;
    void                               *buf;
    volatile uint32_t                  *db;
    uint16_t                           free_idx;   /* what is completed contiguously */
    uint16_t                           ready_idx;  /* what is ready to be posted to hw */
    uint16_t                           sw_pi;      /* what is posted to hw */
    uint16_t                           mask;
    uint16_t                           stride;
    int                                num_strides;
    uint16_t                           hdr_offset;
    union {
        struct {
            struct ibv_srq             *srq;
        } verbs;
#if HAVE_DEVX
        struct {
            uct_ib_mlx5_dbrec_t        *dbrec;
            uct_ib_mlx5_devx_umem_t    mem;
            struct mlx5dv_devx_obj     *obj;
        } devx;
#endif
    };
} uct_ib_mlx5_srq_t;


typedef struct {
    uct_recv_desc_t             super;
    unsigned                    offset;
} uct_ib_mlx5_release_desc_t;


/**
 * SRQ segment
 *
 * We add some SW book-keeping information in the unused HW fields:
 *  - desc           - the receive descriptor.
 *  - strides        - Number of available strides in this WQE. When it is 0,
 *                     this segment can be reposted to the HW. Relevant for
 *                     Multi-Packet SRQ only.
 *  - free           - points to the next out-of-order completed segment.
 */
typedef struct {
    union {
        struct mlx5_wqe_srq_next_seg   mlx5_srq;
        struct {
            uint16_t                   ptr_mask;
            uint16_t                   next_wqe_index; /* Network byte order */
            uint8_t                    signature;
            uint8_t                    rsvd1[1];
            uint8_t                    strides;
            uint8_t                    free;           /* Released but not posted */
            union {
                uct_ib_iface_recv_desc_t   *desc;          /* Host byte order */
                void                   *desc_v;
            };
        } srq;
    };
    struct mlx5_wqe_data_seg           dptr[0];
} uct_ib_mlx5_srq_seg_t;


#if HAVE_DEVX
ucs_status_t
uct_ib_mlx5_devx_init_rx_common(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                                uct_ib_mlx5_srq_attr_t *attr, void *wq);

ucs_status_t
uct_ib_mlx5_devx_init_rx(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                         uct_ib_mlx5_srq_attr_t *attr);

void uct_ib_mlx5_devx_cleanup_srq(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq);
#else
static UCS_F_MAYBE_UNUSED ucs_status_t
uct_ib_mlx5_devx_init_rx_common(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                                uct_ib_mlx5_srq_attr_t *attr, void *wq)
{
    return UCS_ERR_UNSUPPORTED;
}

static UCS_F_MAYBE_UNUSED ucs_status_t
uct_ib_mlx5_devx_init_rx(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                         uct_ib_mlx5_srq_attr_t *attr);
{
    return UCS_ERR_UNSUPPORTED;
}

static UCS_F_MAYBE_UNUSED void
uct_rc_mlx5_devx_cleanup_srq(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq)
{
    ucs_bug("DEVX SRQ cleanup has to be done only if DEVX support is enabled");
}
#endif

/**
 * Initialize srq structure.
 */
ucs_status_t
uct_ib_mlx5_verbs_srq_init(uct_ib_mlx5_srq_t *srq, struct ibv_srq *verbs_srq,
                           size_t sg_byte_count, int num_sge);

void uct_ib_mlx5_srq_buff_init(uct_ib_mlx5_srq_t *srq,
                               uct_ib_mlx5_srq_attr_t *attr);

void uct_ib_mlx5_release_desc(uct_recv_desc_t *self, void *desc);

#endif

/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_RX_INL_
#define UCT_IB_MLX5_RX_INL_

#include "rx.h"
#include "ib_mlx5.inl"

static inline uct_ib_mlx5_srq_seg_t *
uct_ib_mlx5_srq_get_wqe(uct_ib_mlx5_srq_t *srq, uint16_t wqe_index)
{
    return UCS_PTR_BYTE_OFFSET(srq->buf, (wqe_index & srq->mask) * srq->stride);
}

static UCS_F_ALWAYS_INLINE int uct_ib_mlx5_srq_stride(int num_sge)
{
    int stride;

    stride = sizeof(struct mlx5_wqe_srq_next_seg) +
             (num_sge * sizeof(struct mlx5_wqe_data_seg));

    return ucs_roundup_pow2(stride);
}

static UCS_F_ALWAYS_INLINE int
uct_ib_mlx5_srq_max_wrs(int rxq_len, int num_sge)
{
    return ucs_roundup_pow2(ucs_max(rxq_len / num_sge,
                                    UCT_IB_MLX5_XRQ_MIN_UWQ_POST));
}

/* Update resources and write doorbell record */
static UCS_F_ALWAYS_INLINE void
uct_ib_mlx5_iface_update_srq_res(uct_ib_mlx5_srq_t *srq,
                                 uint16_t wqe_index, uint16_t count)
{
    ucs_assert(srq->super.available >= count);

    if (count == 0) {
        return;
    }

    srq->ready_idx              = wqe_index;
    srq->sw_pi                 += count;
    srq->super.available       -= count;
    ucs_memory_cpu_store_fence();
    *srq->db                    = htonl(srq->sw_pi);
}

static UCS_F_NOINLINE void
uct_ib_mlx5_iface_hold_srq_desc(uct_ib_mlx5_srq_t *srq,
                                uct_ib_mlx5_srq_seg_t *seg,
                                struct mlx5_cqe64 *cqe, uint16_t wqe_ctr,
                                ucs_status_t status, unsigned offset,
                                uct_recv_desc_t *release_desc)
{
    void *udesc;
    int stride_idx;
    int desc_offset;

    if (srq->num_strides > 1) {
        /* stride_idx is valid in non inline CQEs only.
         * We can assume that stride_idx is correct here, because CQE
         * with data would always force upper layer to save the data and
         * return UCS_OK from the corresponding callback. */
        stride_idx = uct_ib_mlx5_cqe_stride_index(cqe);
        ucs_assert(stride_idx < srq->num_strides);
        ucs_assert(!(cqe->op_own & (MLX5_INLINE_SCATTER_32 |
                                    MLX5_INLINE_SCATTER_64)));

        udesc       = (void*)be64toh(seg->dptr[stride_idx].addr);
        desc_offset = offset - srq->hdr_offset;
        udesc       = UCS_PTR_BYTE_OFFSET(udesc, desc_offset);
        uct_recv_desc(udesc) = release_desc;
        seg->srq.ptr_mask   &= ~UCS_BIT(stride_idx);
    } else {
        udesc                = UCS_PTR_BYTE_OFFSET(seg->srq.desc, offset);
        uct_recv_desc(udesc) = release_desc;
        seg->srq.ptr_mask   &= ~1;
        seg->srq.desc        = NULL;
    }
}

static UCS_F_ALWAYS_INLINE void
uct_ib_mlx5_iface_release_srq_seg(uct_ib_mlx5_srq_t *srq,
                                  uct_ib_mlx5_srq_seg_t *seg,
                                  struct mlx5_cqe64 *cqe, uint16_t wqe_ctr,
                                  ucs_status_t status, unsigned offset,
                                  uct_recv_desc_t *release_desc, int poll_flags)
{
    uint16_t wqe_index;
    int seg_free;

    /* Need to wrap wqe_ctr, because in case of cyclic srq topology
     * it is wrapped around 0xFFFF regardless of real SRQ size.
     * But it respects srq size when srq topology is a linked-list. */
    wqe_index = wqe_ctr & srq->mask;

    if (ucs_unlikely(status != UCS_OK)) {
        uct_ib_mlx5_iface_hold_srq_desc(srq, seg, cqe, wqe_ctr, status,
                                        offset, release_desc);
    }

    if (srq->num_strides > 1) {
        if (--seg->srq.strides) {
            /* Segment can't be freed until all strides are consumed */
            return;
        }
        seg->srq.strides = srq->num_strides;
    }

    ++srq->super.available;

    if (poll_flags & UCT_IB_MLX5_POLL_FLAG_LINKED_LIST) {
        seg                     = uct_ib_mlx5_srq_get_wqe(srq, srq->free_idx);
        seg->srq.next_wqe_index = htons(wqe_index);
        srq->free_idx           = wqe_index;
        return;
    }

    seg_free = (seg->srq.ptr_mask == UCS_MASK(srq->num_strides));

    if (ucs_likely(seg_free && (wqe_ctr == (srq->ready_idx + 1)))) {
         /* If the descriptor was not used - if there are no "holes", we can just
          * reuse it on the receive queue. Otherwise, ready pointer will stay behind
          * until post_recv allocated more descriptors from the memory pool, fills
          * the holes, and moves it forward.
          */
         ucs_assert(wqe_ctr == (srq->free_idx + 1));
         ++srq->ready_idx;
         ++srq->free_idx;
         return;
    }

    if (wqe_ctr == (srq->free_idx + 1)) {
        ++srq->free_idx;
    } else {
        /* Mark the segment as out-of-order, post_recv will advance free */
        seg->srq.free = 1;
    }
}

#endif

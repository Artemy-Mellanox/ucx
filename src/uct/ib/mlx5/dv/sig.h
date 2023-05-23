/**
* Copyright (C) 2023, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_SIG_H_
#define UCT_IB_MLX5_SIG_H_

#include <uct/ib/mlx5/ib_mlx5.h>
#include "ib_mlx5_def.h"

#define UCT_IB_MLX5_T10DIF_BLOCK  4048
#define UCT_IB_MLX5_T10DIF_STRIDE 4096

struct uct_ib_mlx5_sig {
    struct ibv_mr          *mr;
    struct mlx5dv_devx_obj *sig_mr;
    uint32_t               sig_key;
    void*                  *dif;
    struct ibv_mr          *dif_mr;
};

ucs_status_t uct_ib_mlx5_sig_create_psv(struct ibv_pd *pd, struct mlx5dv_devx_obj **psv_p,
                                    uint32_t *index_p);


void uct_ib_mlx5_sig_destroy_psv(struct mlx5dv_devx_obj *psv);


ucs_status_t uct_ib_mlx5_sig_mr_init(uct_ib_mlx5_md_t *md,
                                     uct_ib_mlx5_mem_t *memh);


ucs_status_t uct_ib_mlx5_sig_mr_cleanup(uct_ib_mlx5_mem_t *memh);


static inline unsigned uct_ib_mlx5_sig_mr_idx(uct_ib_mlx5_sig_t *sig,
                                              const void *ptr)
{
    return UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr) / UCT_IB_MLX5_T10DIF_STRIDE;
}


static inline ucs_status_t
uct_ib_mlx5_sig_mr_get_data(uct_ib_mlx5_md_t *md, uct_mem_h uct_memh, void *ptr,
                            void **sig_payload_p, uint32_t *sig_key_p)
{
    uct_ib_mlx5_mem_t *memh = (uct_ib_mlx5_mem_t*)uct_memh;
    uct_ib_mlx5_sig_t *sig;
    ucs_status_t status;
    unsigned idx;

    if (!(memh->super.flags & UCT_IB_MEM_SIGNATURE)) {
        status = uct_ib_mlx5_sig_mr_init(md, memh);
        if (status != UCS_OK) {
            return status;
        }
    }

    sig            = memh->mrs[UCT_IB_MR_SIG].sig_ctx;
    idx            = uct_ib_mlx5_sig_mr_idx(sig, ptr);
    *sig_payload_p = (void *)(intptr_t)(idx * UCT_IB_MLX5_T10DIF_BLOCK);
    *sig_key_p     = sig->sig_key;

    return UCS_OK;
}


static inline uint16_t
uct_ib_mlx5_calc_sig(uct_mem_h uct_memh, const void *data, const size_t len)
{
    uct_ib_mlx5_mem_t *memh = (uct_ib_mlx5_mem_t*)uct_memh;
    uct_ib_mlx5_sig_t *sig  = memh->mrs[UCT_IB_MR_SIG].sig_ctx;
    unsigned idx            = uct_ib_mlx5_sig_mr_idx(sig, data);
    struct {
        uint16_t guard;
        uint16_t apptag;
        uint32_t reftag;
    } *t10dif               = UCS_PTR_BYTE_OFFSET(sig->dif, idx * 8);
    size_t num_blocks       = len / UCT_IB_MLX5_T10DIF_BLOCK;
    const uint16_t *p       = UCS_PTR_BYTE_OFFSET(data, UCT_IB_MLX5_T10DIF_BLOCK * num_blocks);
    const uint16_t *end     = UCS_PTR_BYTE_OFFSET(p, (len % UCT_IB_MLX5_T10DIF_BLOCK) - 1);
    uint32_t sum            = 0;
    int i;

    while (p < end) {
        sum += *p++;
    }

    if (len & 1) {
        sum += *(uint8_t *)p;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    for (i = 0; i < num_blocks; i++) {
        sum += (uint16_t)~t10dif[i].guard;
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return ~sum;
}

#endif

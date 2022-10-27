/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_SIG_H_
#define UCT_IB_MLX5_SIG_H_

#include <uct/ib/mlx5/ib_mlx5.h>
#include "ib_mlx5_def.h"

#if HAVE_DEVX

enum {
#if T10DIF_4048
    UCT_IB_MLX5_T10DIF_BLOCK = 4048
#else
    UCT_IB_MLX5_T10DIF_BLOCK = 512
#endif
};

ucs_status_t uct_ib_mlx5_create_psv(struct ibv_pd *pd, struct mlx5dv_devx_obj **psv_p,
                                    uint32_t *index_p);
void uct_ib_mlx5_destroy_psv(struct mlx5dv_devx_obj *psv);

ucs_status_t uct_ib_mlx5_sig_mr_init(uct_ib_mlx5_md_t *md,
                                     uct_ib_mlx5_mem_t *memh);

static inline uct_ib_mlx5_sig_t *
uct_ib_mlx5_sig_mr_get_ctx(uct_ib_mlx5_md_t *md, uct_mem_h uct_memh)
{
    uct_ib_mlx5_mem_t *memh = (uct_ib_mlx5_mem_t*)uct_memh;
    ucs_status_t UCS_V_UNUSED status;

    ucs_assert(memh != UCT_MEM_HANDLE_NULL);
    if (!(memh->super.flags & UCT_IB_MEM_SIG)) {
        ucs_assert(md != NULL);
        status = uct_ib_mlx5_sig_mr_init(md, memh);
        ucs_assert(status == UCS_OK);
    }

    return memh->mrs[UCT_IB_MR_SIG].sig_ctx;
}

static inline void *
uct_ib_mlx5_sig_mr_get_dif(uct_ib_mlx5_md_t *md, uct_mem_h memh, void *ptr)
{
    uct_ib_mlx5_sig_t *sig = uct_ib_mlx5_sig_mr_get_ctx(md, memh);
    //unsigned idx = UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr) / 512;
    unsigned idx = UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr) / 4096;

    return UCS_PTR_BYTE_OFFSET(sig->dif, idx * 8);
}

static inline void
uct_ib_mlx5_sig_mr_get_data(uct_ib_mlx5_md_t *md, uct_mem_h memh, void *ptr,
                            void **sig_payload_p, uint32_t *sig_key_p)
{
    uct_ib_mlx5_sig_t *sig = uct_ib_mlx5_sig_mr_get_ctx(md, memh);

#if T10DIF_4048
    unsigned idx = UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr) / 4096;
    *sig_payload_p = (void *)(intptr_t)(idx * 4048);
    *sig_key_p = sig->sig_key;
#else
    *sig_payload_p = (void *)UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr);
    *sig_key_p = sig->sig_key;
#endif
}

void uct_ib_mlx5_sig_cleanup(uct_ib_mlx5_sig_t *sig);

static inline uint16_t uct_ib_mlx5_ipcs(void *ptr, size_t len)
{
    uint32_t sum = 0;
    uint16_t *data = (uint16_t *)ptr;

    if (len == 0) {
        return 0;
    }

    while (1) {
        sum += *data;
        data++;
        len -= 2;
        //if ((len -= 2) & 0x0f) continue;
        sum = (sum & 0xffff) + (sum >> 16);
        if (len < 2) {
            break;
        }
    }

    if (len == 1) {
        sum += *(uint8_t *)data;
    }

    return sum;
}

static inline uint16_t
uct_ib_mlx5_calc_sig(uct_mem_h memh, void *data, size_t len)
{
    struct {
        uint16_t guard;
        uint16_t apptag;
        uint32_t reftag;
    } *t10dif = uct_ib_mlx5_sig_mr_get_dif(NULL, memh, data);

    size_t num_blocks = len / UCT_IB_MLX5_T10DIF_BLOCK;
    uint32_t sum;
    int i;

    data = UCS_PTR_BYTE_OFFSET(data, UCT_IB_MLX5_T10DIF_BLOCK * num_blocks);
    sum = uct_ib_mlx5_ipcs(data, len % UCT_IB_MLX5_T10DIF_BLOCK);

    for (i = 0; i < num_blocks; i++) {
        sum += (uint16_t)~t10dif[i].guard;
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

#else

#endif

#endif

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
    UCT_IB_MLX5_T10DIF_BLOCK = 512, //*8,
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
    unsigned idx = UCS_PTR_BYTE_DIFF(sig->mr->addr, ptr) / 512;

    return UCS_PTR_BYTE_OFFSET(sig->dif, idx * 8);
}

static inline void
uct_ib_mlx5_sig_mr_get_data(uct_ib_mlx5_md_t *md, uct_mem_h memh, void *payload,
                            void **sig_payload_p, uint32_t *sig_key_p)
{
    uct_ib_mlx5_sig_t *sig = uct_ib_mlx5_sig_mr_get_ctx(md, memh);

    *sig_payload_p = (void *)UCS_PTR_BYTE_DIFF(sig->mr->addr, payload);
    *sig_key_p = sig->sig_key;
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

    return (uint16_t)~((sum & 0xffff) + (sum >> 16));
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
    uint16_t guard;
    //void *tmp = data;
    int i;

    data  = UCS_PTR_BYTE_OFFSET(data, UCT_IB_MLX5_T10DIF_BLOCK * num_blocks);
    guard = uct_ib_mlx5_ipcs(data, len % UCT_IB_MLX5_T10DIF_BLOCK);

    ucs_memory_cpu_load_fence();
    //printf("%s:%d %p %p %zd %x\n", __func__, __LINE__, data, t10dif, len, guard);
    for (i = 0; i < num_blocks; i++) {
        guard += t10dif->guard;
        //printf("%s:%d %x %x %x\n", __func__, __LINE__, t10dif->guard, guard, uct_ib_mlx5_ipcs(UCS_PTR_BYTE_OFFSET(tmp, UCT_IB_MLX5_T10DIF_BLOCK * i), UCT_IB_MLX5_T10DIF_BLOCK));
        t10dif++;
    }

    return guard;
}

#else

#endif

#endif

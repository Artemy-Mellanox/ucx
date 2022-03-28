/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_SIG_H_
#define UCT_IB_MLX5_SIG_H_

#include "ib_mlx5.h"
#include "rx.h"

typedef struct {
    uct_ib_mlx5_md_t           *md;
    uct_ib_mlx5_srq_t          *srq;
    uct_ib_mlx5_cq_t           *cq;
    ucs_mpool_t                *mp;
    struct mlx5dv_devx_obj     *psv;
    uint32_t                   psv_idx;
    size_t                     payload_offset;
    size_t                     hdr_offset;
    uct_ib_mlx5_release_desc_t desc;
    unsigned                   num_alloc_methods;
    uct_alloc_method_t         *alloc_methods;
    unsigned                   max_batch;
} uct_ib_mlx5_sig_t;


#if HAVE_DEVX

unsigned uct_ib_mlx5_poll_sig(uct_ib_iface_t *iface, uct_ib_mlx5_sig_t *sig);

ucs_status_t uct_ib_mlx5_sig_init(uct_ib_mlx5_md_t *md,
                                  const uct_iface_params_t *params,
                                  const uct_ib_iface_config_t *config,
                                  uct_ib_mlx5_srq_t *srq,
                                  ucs_mpool_t *mp,
                                  uct_ib_mlx5_cq_t *cq,
                                  uct_ib_mlx5_sig_t **sig_p);

void uct_ib_mlx5_sig_cleanup(uct_ib_mlx5_sig_t *sig);

#else

#endif

#endif

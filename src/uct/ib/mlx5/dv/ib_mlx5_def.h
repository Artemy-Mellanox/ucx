/**
* Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2022. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_DEF_H_
#define UCT_IB_MLX5_DEF_H_

#include "sig_def.h"

typedef struct {
    struct mlx5dv_devx_obj     *dvmr;
    int                        mr_num;
    size_t                     length;
    struct ibv_mr              *mrs[];
} uct_ib_mlx5_ksm_data_t;


typedef union uct_ib_mlx5_mr {
    uct_ib_mr_t                super;
    uct_ib_mlx5_ksm_data_t     *ksm_data;
#if HAVE_DEVX
    uct_ib_mlx5_sig_t          *sig_ctx;
#endif
} uct_ib_mlx5_mr_t;


typedef struct uct_ib_mlx5_mem {
    uct_ib_mem_t               super;
#if HAVE_DEVX
    struct mlx5dv_devx_obj     *atomic_dvmr;
    struct mlx5dv_devx_obj     *indirect_dvmr;
#endif
    uct_ib_mlx5_mr_t           mrs[];
} uct_ib_mlx5_mem_t;

#endif

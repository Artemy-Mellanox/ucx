/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifndef UCT_IB_MLX5_SIG_DEF_H_
#define UCT_IB_MLX5_SIG_DEF_H_

#include <uct/ib/mlx5/ib_mlx5.h>

#if HAVE_DEVX

typedef struct {
    struct ibv_mr          *mr;
    struct mlx5dv_devx_obj *sig_mr;
    uint32_t               sig_key;
    void*                  *dif;
    struct ibv_mr          *dif_mr;
} uct_ib_mlx5_sig_t;

#endif

#endif

/*
 * Copyright (C) 2021, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */
#include <ucp/api/ucp.h>
#include <ucs/debug/log_def.h>
#include <stdarg.h>

extern ucs_log_func_rc_t handle_log(const char *file, unsigned line,
                                    const char *function, ucs_log_level_t level,
                                    const ucs_log_component_config_t *comp_conf,
                                    const char *message, va_list ap);

extern void ucxgo_handleLog(ucs_log_level_t level, char *file, int line, char *message);

extern void register_handle_log(void);

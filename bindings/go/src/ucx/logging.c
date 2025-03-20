/*
 * Copyright (C) 2025, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "logging.h"
#include "ucs/debug/log_def.h"
#include "ucs/sys/string.h"

ucs_log_func_rc_t handle_log(const char *file, unsigned line,
                             const char *function, ucs_log_level_t level,
                             const ucs_log_component_config_t *comp_conf,
                             const char *message, va_list ap)
{
    const size_t buffer_size = ucs_log_get_buffer_size();
    char *buf = alloca(buffer_size);
    char *short_file = (char *)ucs_basename(file);
    vsnprintf(buf, buffer_size, message, ap);
    ucxgo_handleLog(level, short_file, line, buf);
    return UCS_LOG_FUNC_RC_STOP;
}

void register_handle_log(void)
{
    ucs_log_push_handler(handle_log);
}

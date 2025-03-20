/*
 * Copyright (C) 2025, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

package ucx

// #include "logging.h"
import "C"
import (
	"fmt"
	"log/slog"
)

var logger *slog.Logger

//export ucxgo_handleLog
func ucxgo_handleLog(level C.ucs_log_level_t, file *C.char, line C.int, message *C.char) {
	logger.Info(fmt.Sprintf("%17s:%-4d %s\n", C.GoString(file), int(line), C.GoString(message)))
}

func SetLogger(l *slog.Logger) {
	logger = l
	C.register_handle_log()
}

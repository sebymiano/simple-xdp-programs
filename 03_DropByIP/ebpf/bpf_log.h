#pragma once

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_DISABLED (0)
#define BPF_LOG_ERR (1)
#define BPF_LOG_WARNING (2)
#define BPF_LOG_NOTICE (3)
#define BPF_LOG_INFO (4)
#define BPF_LOG_DEBUG (5)

#ifndef BPF_LOG_LEVEL
#define BPF_LOG_LEVEL BPF_LOG_DISABLED
#endif

#define BPF_LOG_FORMAT(level, fmt, ...) \
    (BPF_LOG_LEVEL < level ? (0) : \
        bpf_printk("%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__))

#define bpf_log_err(fmt, ...) BPF_LOG_FORMAT(BPF_LOG_ERR, fmt, ##__VA_ARGS__)
#define bpf_log_warning(fmt, ...) BPF_LOG_FORMAT(BPF_LOG_WARNING, fmt, ##__VA_ARGS__)
#define bpf_log_notice(fmt, ...) BPF_LOG_FORMAT(BPF_LOG_NOTICE, fmt, ##__VA_ARGS__)
#define bpf_log_info(fmt, ...) BPF_LOG_FORMAT(BPF_LOG_INFO, fmt, ##__VA_ARGS__)
#define bpf_log_debug(fmt, ...) BPF_LOG_FORMAT(BPF_LOG_DEBUG, fmt, ##__VA_ARGS__)
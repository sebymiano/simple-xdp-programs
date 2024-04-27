#ifndef HHD_V1_H_
#define HHD_V1_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>

#include <cyaml/cyaml.h>
#include <sys/types.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"

// Include skeleton file
#include "hhd_v1.skel.h"

static int ifindex_iface1 = 0;
static int ifindex_iface2 = 0;
static int ifindex_iface3 = 0;
static int ifindex_iface4 = 0;
static __u32 xdp_flags = 0;

struct ip {
    const char *ip;
    uint64_t threshold;
    uint32_t port;
};

struct ips {
    struct ip *ips;
    uint64_t ips_count;
};

static const cyaml_schema_field_t ip_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct ip, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("threshold", CYAML_FLAG_DEFAULT, struct ip, threshold),
    CYAML_FIELD_UINT("port", CYAML_FLAG_DEFAULT, struct ip, port),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t ip_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct ip, ip_field_schema),
};

static const cyaml_schema_field_t ips_field_schema[] = {
    CYAML_FIELD_SEQUENCE("ips", CYAML_FLAG_POINTER, struct ips, ips, &ip_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t ips_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ips, ips_field_schema),
};

static const cyaml_config_t config = {
	.log_fn = cyaml_log,            /* Use the default logging function. */
	.mem_fn = cyaml_mem,            /* Use the default memory allocator. */
	.log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface1 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface1, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface1);
            }
        }
    }

    if (ifindex_iface2 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface2, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface2, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface2);
            }
        }
    }

    if (ifindex_iface3 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface3, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface3, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface3);
            }
        }
    }

    if (ifindex_iface4 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface4, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface4, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface4);
            }
        }
    }
}

int attach_bpf_progs(unsigned int xdp_flags, struct hhd_v1_bpf *skel) {
    int err = 0;
    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.xdp_hhdv1), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 1st XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface2, bpf_program__fd(skel->progs.xdp_hhdv1), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 2nd XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface3, bpf_program__fd(skel->progs.xdp_hhdv1), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 3rd XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface4, bpf_program__fd(skel->progs.xdp_hhdv1), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 4th XDP program to the interface");
        return err;
    }

    return 0;
}

static void get_iface_ifindex(const char *iface1, const char *iface2, const char *iface3, const char *iface4) {
    if (iface1 == NULL) {
        log_warn("No interface specified, using default one (veth1)");
        iface1 = "veth1";
    }

    log_info("XDP program will be attached to %s interface", iface1);
    ifindex_iface1 = if_nametoindex(iface1);
    if (!ifindex_iface1) {
        log_fatal("Error while retrieving the ifindex of %s", iface1);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
    }

    if (iface2 == NULL) {
        log_warn("No interface specified, using default one (veth2)");
        iface2 = "veth2";
    }

    log_info("XDP program will be attached to %s interface", iface2);
    ifindex_iface2 = if_nametoindex(iface2);
    if (!ifindex_iface2) {
        log_fatal("Error while retrieving the ifindex of %s", iface2);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface2, ifindex_iface2);
    }

    if (iface3 == NULL) {
        log_warn("No interface specified, using default one (veth3)");
        iface3 = "veth3";
    }

    log_info("XDP program will be attached to %s interface", iface3);
    ifindex_iface3 = if_nametoindex(iface3);
    if (!ifindex_iface3) {
        log_fatal("Error while retrieving the ifindex of %s", iface3);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface3, ifindex_iface3);
    }

    if (iface4 == NULL) {
        log_warn("No interface specified, using default one (veth3)");
        iface4 = "veth4";
    }

    log_info("XDP program will be attached to %s interface", iface4);
    ifindex_iface4 = if_nametoindex(iface4);
    if (!ifindex_iface4) {
        log_fatal("Error while retrieving the ifindex of %s", iface4);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface4, ifindex_iface4);
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

#endif //HHD_V1_H_

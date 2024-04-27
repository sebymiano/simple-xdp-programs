// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/if_link.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"

// Include skeleton file
#include "xdp_loader.skel.h"

static int ifindex_iface1 = 0;
static __u32 xdp_flags = 0;

static const char *const usages[] = {
    "xdp_loader [options] [[--] args]",
    "xdp_loader [options]",
    NULL,
};

// static void cleanup_ifaces() {
//     __u32 curr_prog_id = 0;

//     if (ifindex_iface1 != 0) {
//         if (!bpf_xdp_query_id(ifindex_iface1, xdp_flags, &curr_prog_id)) {
//             if (curr_prog_id) {
//                 bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
//                 log_trace("Detached XDP program from interface %d", ifindex_iface1);
//             }
//         }
//     }
// }

int main(int argc, const char **argv) {
    struct xdp_loader_bpf *skel = NULL;
    int err;
    const char *iface1 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('i', "iface", &iface1, "Interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\n[Exercise 1] This software attaches an XDP program to the interface specified in the input parameter", 
    "\nIf '-p' argument is specified, the interface will be put in promiscuous mode");
    argc = argparse_parse(&argparse, argc, argv);

    if (iface1 != NULL) {
        log_info("XDP program will be attached to %s interface", iface1);
        ifindex_iface1 = if_nametoindex(iface1);
        if (!ifindex_iface1) {
            log_fatal("Error while retrieving the ifindex of %s", iface1);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    /* Open BPF application */
    skel = xdp_loader_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_pass_func, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (xdp_loader_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.xdp_pass_func), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching XDP program to the interface");
        exit(1);
    }

    log_info("Successfully attached!");

    xdp_loader_bpf__destroy(skel);
    return 0;
}
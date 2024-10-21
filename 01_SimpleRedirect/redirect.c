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
#include "redirect.skel.h"

/* TODO 3: Redefine the datarec structure in userspace*/
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

static int ifindex_iface = 0;
static int redir_ifindex_iface = 0;
static __u32 xdp_flags = 0;

static const char *const usages[] = {
    "redirect [options] [[--] args]",
    "redirect [options]",
    NULL,
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface != 0) {
        if (!bpf_xdp_query_id(ifindex_iface, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface);
            }
        }
    }

    if (redir_ifindex_iface != 0) {
        if (!bpf_xdp_query_id(redir_ifindex_iface, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(redir_ifindex_iface, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", redir_ifindex_iface);
            }
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

void poll_stats(struct redirect_bpf *skel) {
    /* TODO 1: get the map file descriptor for the skeleton */
    int map_fd = 0;
    
    map_fd = bpf_map__fd(skel->maps.xdp_stats_map);
    if (map_fd < 0) {
        log_fatal("Error while retrieving the map file descriptor");
        exit(1);
    }

    struct datarec old_values = {0};

    while(true) {
        /* TODO 2: define the value type (struct datarec) */
        int cpus = libbpf_num_possible_cpus();
        struct datarec values[cpus];
        struct datarec tot_values = {0};
        int key = 0;
        int err = 0;
        
        /* TODO 4: get the value of the map for the key 0 */
        err = bpf_map_lookup_elem(map_fd, &key, &values);
        if (err != 0) {
            log_fatal("Error while retrieving the value from the map");
            exit(1);
        }

        for (int i = 0; i < cpus; i++) {
            tot_values.rx_packets += values[i].rx_packets;
            tot_values.rx_bytes += values[i].rx_bytes;
        }


        if (tot_values.rx_packets == 0 && tot_values.rx_bytes == 0) {
            continue;
        }
        
        /* TODO 5: print the number of packets received */
        log_info("Number of packets received: %llu", tot_values.rx_packets - old_values.rx_packets);
        /* TODO 6: print the number of bytes received */
        log_info("Number of bytes received: %llu", tot_values.rx_bytes - old_values.rx_bytes);

        old_values.rx_packets = tot_values.rx_packets;
        old_values.rx_bytes = tot_values.rx_bytes;
        sleep(1);
    }
}

int main(int argc, const char **argv) {
    struct redirect_bpf *skel = NULL;
    int err;
    const char *iface = NULL;
    const char *redir_iface = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('i', "iface", &iface, "Interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('r', "redir_iface", &redir_iface, "Interface where to redirect packets", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\n[Exercise 1] This software attaches an XDP program to the interface specified in the input parameter", 
    "\nIf '-p' argument is specified, the interface will be put in promiscuous mode");
    argc = argparse_parse(&argparse, argc, argv);

    if (iface != NULL) {
        log_info("XDP program will be attached to %s interface", iface);
        ifindex_iface = if_nametoindex(iface);
        if (!ifindex_iface) {
            log_fatal("Error while retrieving the ifindex of %s", iface);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface, ifindex_iface);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    if (redir_iface != NULL) {
        log_info("XDP program will be attached to %s interface", redir_iface);
        redir_ifindex_iface = if_nametoindex(redir_iface);
        if (!redir_ifindex_iface) {
            log_fatal("Error while retrieving the ifindex of %s", redir_iface);
            exit(1);
        } else {
            log_info("Got ifindex for redir_iface: %s, which is %d", redir_iface, redir_ifindex_iface);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    /* Open BPF application */
    skel = redirect_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_prog_map, BPF_PROG_TYPE_XDP);
    bpf_program__set_type(skel->progs.xdp_pass, BPF_PROG_TYPE_XDP);

    skel->rodata->redir_ifindex = redir_ifindex_iface;

    /* Load and verify BPF programs */
    if (redirect_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface, bpf_program__fd(skel->progs.xdp_prog_map), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching the XDP program to the interface");
        goto cleanup;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(redir_ifindex_iface, bpf_program__fd(skel->progs.xdp_pass), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching the XDP program to the interface");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(1);

    poll_stats(skel);

cleanup:
    cleanup_ifaces();
    redirect_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}
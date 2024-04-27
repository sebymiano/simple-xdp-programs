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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"
#include "hhd_v1.h"

struct map_value_t {
   __u64 threshold;
   __u64 packets_rcvd;
};

static const char *const usages[] = {
    "hhd_v1 [options] [[--] args]",
    "hhd_v1 [options]",
    NULL,
};

int load_maps_config(const char *config_file, struct hhd_v1_bpf *skel) {
    struct ips *ips;
    cyaml_err_t err;
    int ret = EXIT_SUCCESS;

    /* Load input file. */
	err = cyaml_load_file(config_file, &config, &ips_schema, (void **) &ips, NULL);
	if (err != CYAML_OK) {
		fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
		return EXIT_FAILURE;
	}

    log_info("Loaded %d IPs", ips->ips_count);

    // Get file descriptor of the map
    int threshold_map_fd = bpf_map__fd(skel->maps.threshold_map);

    // Check if the file descriptor is valid
    if (threshold_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    /* Load the IPs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        log_info("Loading IP %s", ips->ips[i].ip);
        log_info("Threshold: %d", ips->ips[i].threshold);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, ips->ips[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", ips->ips[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // Now write the IP to the BPF map
        struct map_value_t value = {
            .threshold = ips->ips[i].threshold,
            .packets_rcvd = 0,
        };

        ret = bpf_map_update_elem(threshold_map_fd, &addr.s_addr, &value, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }        
    }

    // Get fd of port map
    int port_map_fd = bpf_map__fd(skel->maps.ip_to_port);

    // Check if the file descriptor is valid
    if (port_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    /* Load the IPs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        log_info("Loading IP %s", ips->ips[i].ip);
        log_info("Port: %d", ips->ips[i].port);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, ips->ips[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", ips->ips[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        uint32_t port = ips->ips[i].port;

        ret = bpf_map_update_elem(port_map_fd, &addr.s_addr, &port, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }        
    }

cleanup_yaml:
    /* Free the data */
	cyaml_free(&config, &ips_schema, ips, 0);

    return ret;
}

int main(int argc, const char **argv) {
    struct hhd_v1_bpf *skel = NULL;
    int err;
    const char *config_file = NULL;
    const char *iface1 = NULL;
    const char *iface2 = NULL;
    const char *iface3 = NULL;
    const char *iface4 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
        OPT_STRING('1', "iface1", &iface1, "1st interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('2', "iface2", &iface2, "2nd interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('3', "iface3", &iface2, "3rd interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('4', "iface4", &iface2, "4th interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\n[Exercise 6] This software attaches an XDP program to the interface specified in the input parameter", 
    "\nThe '-1/2/3/4' argument is used to specify the interface where to attach the program");
    argc = argparse_parse(&argparse, argc, argv);

    if (config_file == NULL) {
        log_warn("Use default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    /* Check if file exists */
    if (access(config_file, F_OK) == -1) {
        log_fatal("Configuration file %s does not exist", config_file);
        exit(1);
    }

    get_iface_ifindex(iface1, iface2, iface3, iface4);

    /* Open BPF application */
    skel = hhd_v1_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Add iface configuration to hhd_v1.cfg */
    skel->rodata->hhdv1_cfg.ifindex_if1 = ifindex_iface1;
    skel->rodata->hhdv1_cfg.ifindex_if2 = ifindex_iface2;
    skel->rodata->hhdv1_cfg.ifindex_if3 = ifindex_iface3;
    skel->rodata->hhdv1_cfg.ifindex_if4 = ifindex_iface4;

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_hhdv1, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (hhd_v1_bpf__load(skel)) {
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

    /* Before attaching the program, we can load the map configuration */
    err = load_maps_config(config_file, skel);
    if (err) {
        log_fatal("Error while loading map configuration");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    err = attach_bpf_progs(xdp_flags, skel);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(10000);

cleanup:
    cleanup_ifaces();
    hhd_v1_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}
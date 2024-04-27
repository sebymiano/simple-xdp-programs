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
#include "drop_ip.h"

#define ONE_MILLION 1000000
#define ONE_BILLION 1000000000

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

static const char *const usages[] = {
    "drop_ip [options] [[--] args]",
    "drop_ip [options]",
    NULL,
};

int load_maps_config(const char *config_file, struct drop_ip_bpf *skel) {
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
    int xdp_stats_map_fd = bpf_map__fd(skel->maps.xdp_stats_map);

    // Check if the file descriptor is valid
    if (xdp_stats_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    /* Load the IPs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        log_info("Loading IP %s", ips->ips[i].ip);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, ips->ips[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", ips->ips[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // Now write the IP to the BPF map
        struct datarec value = {
            .rx_bytes = 0,
            .rx_packets = 0,
        };

        ret = bpf_map_update_elem(xdp_stats_map_fd, &addr.s_addr, &value, BPF_ANY);
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

void poll_stats(struct drop_ip_bpf *skel) {
    /* TODO 1: get the map file descriptor for the skeleton */
    int map_fd = 0;
    __u64 prev[2] = {0};
    map_fd = bpf_map__fd(skel->maps.xdp_stats_map);
    if (map_fd < 0) {
        log_fatal("Error while retrieving the map file descriptor");
        exit(1);
    }

    while (true) {
        struct datarec value;
        int key = 0;
        int err = 0;
        float bit_rate, rate;
        __u64 sum[2] = {0};
        // Get the first key
        err = bpf_map_get_next_key(map_fd, NULL, &key);
        if (err) {
            log_fatal("Error while retrieving the first key");
            exit(1);
        }

        do {
            err = bpf_map_lookup_elem(map_fd, &key, &value);
            if (err) {
                log_fatal("Error while retrieving the value from the map");
                exit(1);
            }

            if (value.rx_packets != 0 || value.rx_bytes != 0) {
                // log_info("Key: %d, Number of packets received: %llu", key, value.rx_packets);
                // log_info("Key: %d, Number of bytes received: %llu", key, value.rx_bytes);
                sum[0] += value.rx_packets;
                sum[1] += value.rx_bytes;
            }

            // Save the current key
            int old_key = key;
            // Attempt to get the next key
            err = bpf_map_get_next_key(map_fd, &old_key, &key);
            // If there are no more keys, break from the loop
            if (err) {
                break;
            }
        } while (true);

        if (sum[0] > prev[0]) {
            rate = (sum[0] - prev[0]) / ONE_MILLION;
            log_info("%10llu pkt/s (%.2f Mpps)", (sum[0] - prev[0]) / 1, rate);
        }

        if (sum[1] > prev[1]) {
            bit_rate = (((sum[1] - prev[1]) / 1.0) * 8) / ONE_BILLION;
            log_info("%10llu byte/s (%.2f Gbps)", (sum[1] - prev[1]) / 1,
                     bit_rate);
        }

        prev[0] = sum[0];
        prev[1] = sum[1];

        sleep(1); // Sleep for a bit before starting over
    }
}

int main(int argc, const char **argv) {
    struct drop_ip_bpf *skel = NULL;
    int err;
    const char *config_file = NULL;
    const char *iface1 = NULL;
    const char *iface2 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
        OPT_STRING('1', "iface1", &iface1, "1st interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('2', "iface2", &iface2, "2nd interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\n[Exercise 6] This software attaches an XDP program to the interface specified in the input parameter", 
    "\nThe '-1/2' argument is used to specify the interface where to attach the program");
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

    get_iface_ifindex(iface1, iface2);

    /* Open BPF application */
    skel = drop_ip_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Add iface configuration to drop_ip.cfg */
    skel->rodata->drop_ip_cfg.ifindex_if1 = ifindex_iface1;
    skel->rodata->drop_ip_cfg.ifindex_if2 = ifindex_iface2;

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_drop_by_ip, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (drop_ip_bpf__load(skel)) {
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
    // err = load_maps_config(config_file, skel);
    // if (err) {
    //     log_fatal("Error while loading map configuration");
    //     goto cleanup;
    // }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    err = attach_bpf_progs(xdp_flags, skel);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }

    log_info("Successfully attached!");
    sleep(1000);
    // poll_stats(skel);

cleanup:
    cleanup_ifaces();
    drop_ip_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}
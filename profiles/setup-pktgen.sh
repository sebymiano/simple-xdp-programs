#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UBUNTU_SUGGESTED_VERSION=22.04

DEPS_DIR=/opt

function print_system_info {
    echo -e "${COLOR_GREEN}***********************SYSTEM INFO*************************************"
    echo -e "kernel version:" "$(uname -r)"
    echo -e "linux release info:" "$(lsb_release -d | awk '{print $2, $3}')"
    echo -e "${COLOR_OFF}"
}

function error_message {
    set +x
    echo
    echo -e "${COLOR_RED}Error during installation${COLOR_OFF}"
    print_system_info
    exit 1
}

function success_message {
    set +x
    echo
    echo -e "${COLOR_GREEN}Installation completed successfully${COLOR_OFF}"
    exit 0
}

function check_ubuntu_version {
    CURRENT_UBUNTU_VERSION=$(lsb_release -rs)
    if [[ "${CURRENT_UBUNTU_VERSION}" == "${UBUNTU_SUGGESTED_VERSION}" ]]; then
        echo -e "${COLOR_GREEN} Compatible Ubuntu version ${COLOR_OFF}"
    else
        echo -e "${COLOR_RED} WARNING: Ubuntu version: $CURRENT_UBUNTU_VERSION < Suggested version: $UBUNTU_SUGGESTED_VERSION ${COLOR_OFF}"
        echo -e "${COLOR_RED} You can still try to install Morpheus, but the scripts or the installation may fail ${COLOR_OFF}"
        sleep 2
    fi
}

function download_and_install_mlnx_ofed {
    # Detect Ubuntu version
    UBUNTU_VERSION=$(lsb_release -rs)

    # Set MLNX_OFED_VERSION and MLNX_OFED_FILE based on Ubuntu version
    if [ "$UBUNTU_VERSION" = "22.04" ]; then
        MLNX_OFED_VERSION=MLNX_OFED-24.04-0.6.6.0
        MLNX_OFED_FILE=MLNX_OFED_LINUX-24.04-0.6.6.0-ubuntu22.04-x86_64.tgz
    else
        # If the Ubuntu version is not 22.04, set the default values
        MLNX_OFED_VERSION=MLNX_OFED-23.04-1.1.3.0
        MLNX_OFED_FILE=MLNX_OFED_LINUX-23.04-1.1.3.0-ubuntu20.04-x86_64.tgz
    fi

    $SUDO rm -rf /opt/mlnx-ofed
    mkdir -p /opt/mlnx-ofed

    pushd /opt/mlnx-ofed
    curl -L "https://content.mellanox.com/ofed/${MLNX_OFED_VERSION}/${MLNX_OFED_FILE}" | tar xz -C . --strip-components=2

    if [ -z ${MLNX_OFED_APT+x} ]; then
        echo -e "${COLOR_GREEN}Installing Mellanox OFED manually${COLOR_OFF}"
        
        $SUDO ./mlnxofedinstall --with-mft --with-mstflint --dpdk --upstream-libs

        popd
    else
        echo -e "${COLOR_GREEN}Installing Mellanox OFED using apt${COLOR_OFF}"

        echo "deb file:/opt/mlnx-ofed/DEBS ./" | sudo tee /etc/apt/sources.list.d/mlnx_ofed.list
        wget -qO - http://www.mellanox.com/downloads/ofed/RPM-GPG-KEY-Mellanox | sudo apt-key add -
        $SUDO apt update
        $SUDO apt install -y mlnx-ofed-all
        
    fi
}

function download_and_install_dpdk {
    DPDK_DIR=${DEPS_DIR}/dpdk

    if [ -f "$DEPS_DIR/dpdk_installed" ]; then
        return
    fi

    rm -rf "$DPDK_DIR"

    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Download DPDK 23.11 LTS ${COLOR_OFF}"
    mkdir -p "$DPDK_DIR"
    wget https://fast.dpdk.org/rel/dpdk-23.11.tar.xz
    tar -xvf dpdk-23.11.tar.xz -C "$DPDK_DIR" --strip-components 1
    rm dpdk-23.11.tar.xz

    cd "$DPDK_DIR"
    meson build
    cd build
    ninja
    $SUDO ninja install
    sudo ldconfig

    echo -e "${COLOR_GREEN}DPDK is installed ${COLOR_OFF}"
    popd

    touch "${DEPS_DIR}/dpdk_installed"
}

function configure_dpdk_hugepages {
    DPDK_DIR=${DEPS_DIR}/dpdk

    pushd .
    cd "${DPDK_DIR}"/usertools

    $SUDO ./dpdk-hugepages.py -p 1G --setup 10G

    $SUDO ./dpdk-hugepages.py -s

    popd
}

trap error_message ERR

function show_help() {
    usage="$(basename "$0") [-d] [-q]
Script to setup all the repos needed for the packet generator server

-q  Quit setup, do not prompt info"
    echo "$usage"
    echo
}

while getopts :aqh option; do
    case "${option}" in
    a)
        MLNX_OFED_APT=1
        ;;
    q)
        QUIET=1
        ;;
    h | \?)
        show_help
        exit 0
        ;;
    esac
done

echo "Use 'setup_pktgen.sh -h' to show advanced installation options."

if ! command -v sudo &>/dev/null; then
    echo "sudo not available"
    DEBIAN_FRONTEND=noninteractive apt install -yq sudo
fi

[ -z ${SUDO+x} ] && SUDO='sudo'

mkdir -p "${DEPS_DIR}"

set -e

check_ubuntu_version

$SUDO apt update
$SUDO apt full-upgrade -y
PACKAGES=""
PACKAGES+=" git-lfs python3 python3-pip python3-setuptools python3-wheel python3-pyelftools ninja-build" # DPDK
PACKAGES+=" libnuma-dev libelf-dev libcap-dev libpcap-dev libjansson-dev libipsec-mb-dev"                # DPDK
PACKAGES+=" autoconf libcsv-dev"                                                                         # DPDK burst replay
PACKAGES+=" pciutils build-essential cmake linux-headers-$(uname -r) libnuma-dev libtbb2"                # Moongen
PACKAGES+=" tmux texlive-font-utils pdf2svg poppler-utils pkg-config net-tools bash tcpreplay"           # utility libraries
PACKAGES+=" gnuplot gcc-12 libc6-dev-i386 libbfd-dev"                                                    # for generating figures
PACKAGES+=" libtraceevent-dev libbabeltrace-dev libzstd-dev liblzma-dev libperl-dev libslang2-dev libunwind-dev systemtap-sdt-dev libdw-dev libelf-dev"

$SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -yq $PACKAGES"

if ! command -v meson &>/dev/null; then
    $SUDO pip3 install meson
fi

download_and_install_mlnx_ofed
download_and_install_dpdk

echo -e "${COLOR_GREEN}All dependencies installed, let's configure DPDK.${COLOR_OFF}"

configure_dpdk_hugepages

echo -e "${COLOR_GREEN}Hugepages created.${COLOR_OFF}"

success_message

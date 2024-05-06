#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UBUNTU_SUGGESTED_VERSION=22.04

LLVM_VERSION=15

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

function clone_polycube_repo {
    echo -e "${COLOR_GREEN} Cloning Polycube repository ${COLOR_OFF}"
    $SUDO rm -rf polycube >/dev/null
    git clone --branch ${MORPHEUS_POLYCUBE_BRANCH} --recursive ${POLYCUBE_GIT_REPO_URL} polycube --depth 1
    echo -e "${COLOR_GREEN} Polycube repository cloned ${COLOR_OFF}"
}

function download_and_install_mlnx_ofed {
    if [ -f "/opt/mlnx-ofed/ofed_installed" ]; then
      return
    fi

    # Detect Ubuntu version
    UBUNTU_VERSION=$(lsb_release -rs)

    # Set MLNX_OFED_VERSION and MLNX_OFED_FILE based on Ubuntu version
    if [ "$UBUNTU_VERSION" = "22.04" ]; then
        MLNX_OFED_VERSION=MLNX_OFED-24.01-0.3.3.1
        MLNX_OFED_FILE=MLNX_OFED_LINUX-24.01-0.3.3.1-ubuntu22.04-x86_64.tgz
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

        $SUDO ./mlnxofedinstall --with-mft --with-mstflint --dpdk --upstream-libs -q

        popd
    else
        echo -e "${COLOR_GREEN}Installing Mellanox OFED using apt${COLOR_OFF}"

        echo "deb file:/opt/mlnx-ofed/DEBS ./" | sudo tee /etc/apt/sources.list.d/mlnx_ofed.list
        wget -qO - http://www.mellanox.com/downloads/ofed/RPM-GPG-KEY-Mellanox | sudo apt-key add -
        $SUDO apt update
        $SUDO apt install -y mlnx-ofed-all

    fi

    $SUDO touch /opt/mlnx-ofed/ofed_installed
}

function download_and_install_bpftool {
    sudo rm -rf /opt/bpftool
    git clone https://github.com/libbpf/bpftool.git --recurse-submodules /opt/bpftool
    pushd /opt/bpftool
    make -C src
    $SUDO make -C src install
    popd
}

function download_and_install_llvm {
    # Check if there is an argument
    if [ -z "$1" ]; then
        echo "No LLVM version supplied"
        error_message
    fi

    # Check if the argument is a number
    if ! [[ "$1" =~ ^[0-9]+$ ]]; then
        echo "LLVM version is not a number"
        error_message
    fi

    # check llvm and clang versions, if they are equal to the argument, do nothing
    if [ -x "$(command -v llvm-config)" ] && [ -x "$(command -v clang)" ]; then
        LLVM_VERSION=$(llvm-config --version)
        CLANG_VERSION=$(clang --version | head -n 1 | awk '{print $4}')
        # check only the major version
        LLVM_VERSION=${LLVM_VERSION:0:2}
        CLANG_VERSION=${CLANG_VERSION:0:2}
        if [ "$LLVM_VERSION" == "$1" ] && [ "$CLANG_VERSION" == "$1" ]; then
            echo "LLVM and Clang versions are already $1"
            return
        fi
    fi

    wget https://apt.llvm.org/llvm.sh
    chmod +x llvm.sh
    $SUDO ./llvm.sh $1

    chmod +x $DIR/llvm-update-alternatives.sh
    $SUDO $DIR/llvm-update-alternatives.sh $1
}

function download_and_install_xdptools {
    git clone https://github.com/xdp-project/xdp-tools.git --recurse-submodules /opt/xdp-tools
    pushd /opt/xdp-tools

    ./configure
    make

    popd
}

trap error_message ERR

function show_help() {
    usage="$(basename "$0") [-l] <LLVM_VERSION> [-h]
Morpheus installation script

-l  LLVM version to install"
    echo "$usage"
    echo
}

while getopts :lah option; do
    case "${option}" in
    l)
        LLVM_VERSION=${OPTARG}
        ;;
    a)
        MLNX_OFED_APT=1
        ;;
    h | \?)
        show_help
        exit 0
        ;;
    esac
done

echo "Use 'setup_dut.sh -h' to show advanced installation options."

#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if ! command -v sudo &>/dev/null; then
    echo "sudo not available"
    DEBIAN_FRONTEND=noninteractive apt install -yq sudo
fi

sudo apt update

if ! command -v gpgv2 &>/dev/null; then
    echo "gpgv2 not found"
    sudo DEBIAN_FRONTEND=noninteractive apt install -yq gpgv2
fi

sudo DEBIAN_FRONTEND=noninteractive apt install -yq net-tools bash

[ -z ${SUDO+x} ] && SUDO='sudo'

set -e

pushd .
cd ${DIR}

check_ubuntu_version

$SUDO apt update
PACKAGES=""
PACKAGES+=" git-lfs python3 git python3-pip python3-setuptools python3-wheel python3-pyelftools ninja-build" # DPDK
PACKAGES+=" libnuma-dev libelf-dev libcap-dev libpcap-dev libjansson-dev libipsec-mb-dev"                    # DPDK
PACKAGES+=" autoconf libcsv-dev libbfd-dev"                                                                  # DPDK burst replay
PACKAGES+=" pciutils build-essential cmake linux-headers-$(uname -r) libnuma-dev libtbb2"                    # Moongen
PACKAGES+=" tmux texlive-font-utils pdf2svg poppler-utils pkg-config net-tools bash tcpreplay"               # utility libraries
PACKAGES+=" gnuplot"                                                                                         # for generating figures

$SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -yq $PACKAGES"

if ! command -v meson &>/dev/null; then
    $SUDO pip3 install meson
fi

download_and_install_mlnx_ofed
download_and_install_llvm ${LLVM_VERSION}

if git rev-parse --git-dir >/dev/null 2>&1; then
    git submodule init
    git submodule update --recursive
fi

download_and_install_bpftool
download_and_install_xdptools

popd
success_message

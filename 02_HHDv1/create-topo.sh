#!/bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/../libs/helpers.bash"

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth 4
}
trap cleanup ERR

# Enable verbose output
set -x

cleanup
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create two network namespaces and veth pairs
create_veth 4

# Get MAC address using ifconfig
mac1=$(sudo ip netns exec ns1 ifconfig veth1_ | grep ether | awk '{print $2}')
mac2=$(sudo ip netns exec ns2 ifconfig veth2_ | grep ether | awk '{print $2}')
mac3=$(sudo ip netns exec ns3 ifconfig veth3_ | grep ether | awk '{print $2}')
mac4=$(sudo ip netns exec ns4 ifconfig veth4_ | grep ether | awk '{print $2}')

# Update ARP table ns1
sudo ip netns exec ns1 arp -s 10.0.0.2 $mac2
sudo ip netns exec ns1 arp -s 10.0.0.3 $mac3
sudo ip netns exec ns1 arp -s 10.0.0.4 $mac4

# Update ARP table ns2
sudo ip netns exec ns2 arp -s 10.0.0.1 $mac1
sudo ip netns exec ns2 arp -s 10.0.0.3 $mac3
sudo ip netns exec ns2 arp -s 10.0.0.4 $mac4

# Update ARP table ns3
sudo ip netns exec ns3 arp -s 10.0.0.1 $mac1
sudo ip netns exec ns3 arp -s 10.0.0.2 $mac2
sudo ip netns exec ns3 arp -s 10.0.0.4 $mac4

# Update ARP table ns4
sudo ip netns exec ns4 arp -s 10.0.0.1 $mac1
sudo ip netns exec ns4 arp -s 10.0.0.2 $mac2
sudo ip netns exec ns4 arp -s 10.0.0.3 $mac3

sudo ip netns exec ns1 ./xdp_loader -i veth1_
sudo ip netns exec ns2 ./xdp_loader -i veth2_
sudo ip netns exec ns3 ./xdp_loader -i veth3_
sudo ip netns exec ns4 ./xdp_loader -i veth4_

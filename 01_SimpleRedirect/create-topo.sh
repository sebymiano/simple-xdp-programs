#!/bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/../libs/helpers.bash"

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth 1
}
trap cleanup ERR

# Enable verbose output
set -x

cleanup
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create a network namespace and a veth pair
create_veth 1
sudo ifconfig veth1 10.0.0.254/24 up

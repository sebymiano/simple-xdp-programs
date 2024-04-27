# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

all:
	make -C 01_SimpleDrop
	make -C 02_HHDv1
	make -C 03_DropByIP
	make -C 04_XDP_with_md

clean:
	make -C 01_SimpleDrop clean
	make -C 02_HHDv1 clean
	make -C 03_DropByIP clean
	make -C 04_XDP_with_md clean
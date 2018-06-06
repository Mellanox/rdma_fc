#
# Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

CFLAGS  = -Wall -Werror -g -O2
LDFLAGS = -libverbs -lrdmacm
RM      = rm -f

all: rdma_fc

rdma_fc.o: list.h

rdma_fc: rdma_fc.o
	$(CC) rdma_fc.o -o rdma_fc $(LDFLAGS)
	
clean:
	$(RM) rdma_fc.o rdma_fc
	
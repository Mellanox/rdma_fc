# RDMA flow-control demo

This program demonstrates an RDMA_READ-based flow control over RDMA fabric:
- Communication pattern: a single server reads large data from multiple clients 
- Connection are established using rdma_cm library
- RC / DC transports are supported (DC is still not complete)
- Buffers are aligned to 4096 bytes

Flow control scheme:
- Each read operation is limited to "max_read_size" (32768) bytes by default. 
  Larger requests are split to multiple segments of up to `max_read_size`.
- The total number of outstanding reads is limited to `max_outstanding_reads` 
  (8 by default).
- Reads from multiple connections are scheduled  by round-robin.
- The function `do_rdma_reads` implements the above scheme. 


## Server side:
```
./rdma_fc -n 1 -r 32768 -o 8 -i 100
```

## Client side:
```
./rdma_fc <server-address>
```

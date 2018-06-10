# RDMA flow-control demo

This program demonstrates an RDMA_READ-based flow control over RDMA fabric:
- Communication pattern: a single server reads large data from multiple clients 
- Connection are established using rdma_cm library
- RC and DC<sup>1</sup> transports are supported
- Buffers are aligned to 4096 bytes
- A single client can create multiple connections to a server. In this case, the
 `-n` parameter for the server must be the **total** number of connections the
  server should accept.

Flow control scheme:
- Each read operation is limited to "max_read_size" (32768) bytes by default. 
  Larger requests are split to multiple segments of up to `max_read_size`.
- The total number of outstanding reads is limited to `max_outstanding_reads` 
  (8 by default).
- Reads from multiple connections are scheduled  by round-robin.
- The function `do_rdma_reads` implements the above scheme. 

## Server side:
```
./rdma_fc -n 1 -r 32768 -o 8 -i 1000
```

## Client side:
```
./rdma_fc -n 1 <server-address>
```
---
(1) DC support requires the following patches for librdmacm:
 - `librdmacm: copy ah_attr for ROUTE_RESOLVED event`
 - `IB/core: Set address handle attributes for UD ROUTE_RESOLVED event`
 - `IB/core: Set address handle attributes for UD CONNECT event`


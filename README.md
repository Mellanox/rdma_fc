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
(1) DC transport in the test supports RoCE link only (not InfiniBand).
    In addition, it may be needed to pass some of the following parameters to the test:

<table>
	<tr>
		<td>Parameter</td>
		<td>Description</td>
		<td>ah_attr field</td>
		<td>Default value</td>
	</tr>
	<tr>
		<td>-G index</td>
		<td>GID index to use. The full table can be shown  by "show_gids" command</td>
		<td>grh.sgid_index</td>
        <td>3 (usually means RoCEv2 with IPv4)</td>
	</tr>
	<tr>
		<td>-T tclass</td>
		<td>Ethernet DSCP</td>
		<td>grh.traffic_class</td>
		<td>0</td>
	</tr>
	<tr>
		<td>-S sl</td>
		<td>Ethernet priority</td>
		<td>sl</td>
		<td>0</td>
	</tr>
</table>


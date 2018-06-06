/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#define _GNU_SOURCE
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <rdma/rdma_cma.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <malloc.h>
#include <netdb.h>

#include "list.h"


enum log_level {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE
};

enum transport_type {
    XPORT_RC,
    XPORT_DC
};

enum packet_type {
    PACKET_SYN = 1,
    PACKET_FIN = 2
};

#define LOG(_level, _fmt, ...) \
    { \
        if (LOG_LEVEL_##_level <= g_options.log_level) { \
            printf("%12s:%-4d " #_level "  " _fmt "\n", basename(__FILE__), \
                   __LINE__, ## __VA_ARGS__); \
        } \
    }
#define LOG_ERROR(_fmt, ...)   LOG(ERROR, _fmt, ## __VA_ARGS__)
#define LOG_INFO(_fmt, ...)    LOG(INFO,  _fmt, ## __VA_ARGS__)
#define LOG_DEBUG(_fmt, ...)   LOG(DEBUG, _fmt, ## __VA_ARGS__)
#define LOG_TRACE(_fmt, ...)   LOG(TRACE, _fmt, ## __VA_ARGS__)
#define BIT(_index)            (1ul << (_index))
#define DC_KEY                 0x1
#define MEM_ACCESS_FLAGS       (IBV_ACCESS_LOCAL_WRITE  | \
                                IBV_ACCESS_REMOTE_WRITE | \
                                IBV_ACCESS_REMOTE_READ)
#define IB_GRH_SIZE            40
#define NUM_DCI                4
#define MIN(a, b)              ({ \
                                  typeof(a) _a = (a);  \
                                  typeof(b) _b = (b);  \
                                  _a < _b ? _a : _b;   \
                               })
#define MAX(a, b)              ({ \
                                  typeof(a) _a = (a);  \
                                  typeof(b) _b = (b);  \
                                  _a > _b ? _a : _b;   \
                               })

/* Test options */
typedef struct {
    int                       log_level;
    const char                *dest_address;
    unsigned                  port_num;
    unsigned                  conn_backlog;
    unsigned                  num_connections;
    int                       conn_timeout_ms;
    enum transport_type       transport;
    size_t                    rdma_read_size;
    unsigned                  num_iterations;
    size_t                    max_outstanding_reads;
    size_t                    max_read_size;
    size_t                    tx_queue_len;
    size_t                    rx_queue_len;
    size_t                    max_send_sge;
    size_t                    max_recv_sge;
    unsigned                  max_rd_atomic;
    unsigned                  min_rnr_timer;
    unsigned                  xport_timeout;
    unsigned                  rnr_retry;
    unsigned                  xport_retry_cnt;
    unsigned                  traffic_class;
    unsigned                  hop_limit;
    unsigned                  gid_index;
} options_t;

/* Connection to remote peer (on either client or server) */
typedef struct connection connection_t;
struct connection {
    struct rdma_cm_id         *rdma_id;
    struct ibv_ah             *dc_ah;
    uint32_t                  remote_dctn;
    uint32_t                  rkey;
    uint64_t                  remote_addr;
    size_t                    read_offset;
    list_link_t               list;
};

/* Registered memory */
typedef struct {
    void                      *ptr;
    struct ibv_mr             *mr;
} buffer_t;

/* Global test context */
typedef struct {
    struct rdma_event_channel *event_ch;
    struct rdma_cm_id         *listen_cm_id;
    struct rdma_cm_id         *client_cm_id;
    struct ibv_cq             *cq;
    struct ibv_srq            *srq;
    unsigned                  grh_size;
    buffer_t                  recv_buf;
    buffer_t                  rdma_buf;
    struct ibv_exp_dct        *dct;
    struct ibv_qp             *dcis[NUM_DCI];
    connection_t              *conns;
    unsigned                  num_conns;
    unsigned                  num_established;
    unsigned                  num_disconnect;
    unsigned                  num_fin_recvd;
    unsigned                  recv_available;
    unsigned long             num_outstanding_reads;
} test_context_t;

/* Control packet */
typedef struct {
    uint8_t                   type;        /* packet_type */
    uint32_t                  conn_index;  /* index of connection to FIN/SYN */
} packet_t;

/* Private data passed over rdma_cm protocol */
typedef struct {
    uint32_t                  conn_index;  /* Index of connection in the array */
    uint32_t                  dct_num;     /* DCT number (for DC only) */
    uint32_t                  rkey;        /* Remote key for RDMA */
    uint64_t                  virt_addr;   /* Remote buffer address for RDMA */
} conn_priv_t;

static const char* transport_names[] = {
    [XPORT_RC] = "rc",
    [XPORT_DC] = "dc"
};

options_t g_options = {
    .log_level             = LOG_LEVEL_INFO,
    .dest_address          = "",
    .port_num              = 20000,
    .conn_backlog          = 1000,
    .num_connections       = 1,
    .conn_timeout_ms       = 2000,
    .transport             = XPORT_RC,
    .rdma_read_size        = 1024 * 1024,
    .num_iterations        = 1000,
    .max_outstanding_reads = 8,
    .max_read_size         = 32768,
    .tx_queue_len          = 128,
    .rx_queue_len          = 128,
    .max_send_sge          = 1,
    .max_recv_sge          = 1,
    .max_rd_atomic         = 8,
    .min_rnr_timer         = 17,
    .xport_timeout         = 17,
    .rnr_retry             = 7,
    .xport_retry_cnt       = 7,
    .traffic_class         = 0,
    .hop_limit             = 0,
    .gid_index             = 0
};

test_context_t g_test = {
    .event_ch        = NULL,
    .listen_cm_id    = NULL,
    .client_cm_id    = NULL,
    .cq              = NULL,
    .srq             = NULL,
    .recv_buf = {
         .ptr        = NULL,
         .mr         = NULL
     },
    .rdma_buf = {
        .ptr         = NULL,
        .mr          = NULL
    },
    .dct             = NULL,
    .conns           = NULL,
    .num_conns       = 0,
    .num_established = 0,
    .num_disconnect  = 0,
    .num_fin_recvd   = 0,
    .recv_available  = 0
};

static void usage(const options_t *defaults) {
    printf("Usage: many2one [ options ] [ server-address]\n");
    printf("Common options:\n");
    printf("   -p <num>       Server port number to use (%d)\n", defaults->port_num);
    printf("   -x <transport> Which RDMA transport to use (%s)\n", transport_names[defaults->transport]);
    printf("                  possible values are:\n");
    printf("                    'rc' : Reliable Connection (RC) transport\n");
    printf("                    'dc' : Dynamic Connection (DC) transport\n");
    printf("   -T <num>       Traffic class for DCT (%d)\n", defaults->traffic_class);
    printf("   -H <num>       Hop limit for DCT (%d)\n", defaults->hop_limit);
    printf("   -G <num>       GID index for DCT (%d)\n", defaults->gid_index);
    printf("   -v             Increase logging level\n");
    printf("\n");
    printf("Client options:\n");
    printf("   -t <ms>        Connection timeout, milliseconds (%d)\n", defaults->conn_timeout_ms);
    printf("\n");
    printf("Server options:\n");
    printf("   -n <num>       Number of connections to expect (%d)\n", defaults->num_connections);
    printf("   -i <num>       Number of iterations to run (%d)\n", defaults->num_iterations);
    printf("   -r <size>      Maximal size of a single rdma read (%zu)\n", defaults->max_read_size);
    printf("   -o <num>       Maximal number of outstanding reads (%zu)\n", defaults->max_outstanding_reads);
}

static int parse_opts(int argc, char **argv) {
    options_t defaults = g_options;
    int c;

    while ( (c = getopt(argc, argv, "hp:n:vt:x:i:r:o:T:H:G:")) != -1 ) {
        switch (c) {
        case 'p':
            g_options.port_num = atoi(optarg);
            break;
        case 'n':
            g_options.num_connections = atoi(optarg);
            break;
        case 'v':
            ++g_options.log_level;
            break;
        case 't':
            g_options.conn_timeout_ms = atoi(optarg);
            break;
        case 'x':
            if (!strcasecmp(optarg, transport_names[XPORT_RC])) {
                g_options.transport = XPORT_RC;
            } else if (!strcasecmp(optarg, transport_names[XPORT_DC])) {
                g_options.transport = XPORT_DC;
            } else {
                LOG_ERROR("Invalid transport name '%s'", optarg);
                usage(&defaults);
                return -1;
            }
            break;
        case 'i':
            g_options.num_iterations = atoi(optarg);
            break;
        case 'r':
            g_options.max_read_size = atol(optarg);
            break;
        case 'o':
            g_options.max_outstanding_reads = atol(optarg);
            break;
        case 'T':
            g_options.traffic_class = atoi(optarg);
            break;
        case 'H':
            g_options.hop_limit = atoi(optarg);
            break;
        case 'G':
            g_options.gid_index = atoi(optarg);
            break;
        case 'h':
            usage(&defaults);
            exit(0);
        default:
            LOG_ERROR("Invalid option '%c'", c);
            usage(&defaults);
            return -1;
        }
    }

    if (optind < argc) {
        g_options.dest_address    = argv[optind++];
    }

    return 0;
}

static int init_buffer(struct ibv_pd *pd, size_t size, buffer_t *buf)
{
    if (buf->ptr) {
        return 0; /* already initialized */
    }

    buf->ptr = memalign(4096, size);
    if (!buf->ptr) {
        LOG_ERROR("Failed to allocate buffer");
        return -1;
    }

    buf->mr = ibv_reg_mr(pd, buf->ptr, size, MEM_ACCESS_FLAGS);
    if (!buf->mr) {
        LOG_ERROR("ibv_reg_mr() failed: %m");
        return -1;
    }

    LOG_DEBUG("Registered buffer %p length %zu lkey 0x%x rkey 0x%x",
              buf->ptr, size, buf->mr->lkey, buf->mr->rkey);
    return 0;
}

static void cleanup_buffer(buffer_t *buf)
{
    if (buf->ptr) {
        free(buf->ptr);
    }
    if (buf->mr) {
        ibv_dereg_mr(buf->mr);
    }
}

static int init_test()
{
    /* Create rdma_cm event channel */
    g_test.event_ch = rdma_create_event_channel();
    if (!g_test.event_ch) {
        LOG_ERROR("rdma_create_event_channel() failed: %m");
        return -1;
    }

    /* Allocate array of connections */
    g_test.conns = calloc(g_options.num_connections, sizeof(*g_test.conns));
    if (!g_test.conns) {
        LOG_ERROR("failed to allocate connections array");
        return -1;
    }

    /* Set GRH size/offset for DC
     * TODO make DCT scatter the GRH to receive buffer
     */
    g_test.grh_size = (g_options.transport == XPORT_RC) ? 0 : 0;/* TODO IB_GRH_SIZE */;

    return 0;
}

static void cleanup_test()
{
    unsigned i;

    for (i = 0; i < g_test.num_conns; ++i) {
        if (g_test.conns[i].dc_ah) {
            ibv_destroy_ah(g_test.conns[i].dc_ah);
        }
        if (g_test.conns[i].rdma_id != g_test.client_cm_id) {
            rdma_destroy_id(g_test.conns[i].rdma_id);
        }
    }
    for (i = 0; i < NUM_DCI; ++i) {
        if (g_test.dcis[i]) {
            ibv_destroy_qp(g_test.dcis[i]);
        }
    }
    if (g_test.srq) {
        ibv_destroy_srq(g_test.srq);
    }
    if (g_test.cq) {
        ibv_destroy_cq(g_test.cq);
    }
    cleanup_buffer(&g_test.rdma_buf);
    cleanup_buffer(&g_test.recv_buf);
    if (g_test.client_cm_id) {
        rdma_destroy_id(g_test.client_cm_id);
    }
    if (g_test.listen_cm_id) {
        rdma_destroy_id(g_test.listen_cm_id);
    }
    free(g_test.conns);
    rdma_destroy_event_channel(g_test.event_ch);
}

static int get_address(struct sockaddr_in *in_addr)
{
    struct hostent *he = gethostbyname(g_options.dest_address);
    if (!he || !he->h_addr_list) {
        LOG_ERROR("host %s not found: %s", g_options.dest_address,
                  hstrerror(h_errno));
        return -1;
    }

    if (he->h_addrtype != AF_INET) {
        LOG_ERROR("Only IPv4 addresses are supported");
        return -1;
    }

    if (he->h_length != sizeof(struct in_addr)) {
        LOG_ERROR("Mismatching address length");
        return -1;
    }

    memset(in_addr, 0, sizeof(*in_addr));
    in_addr->sin_family = AF_INET;
    in_addr->sin_port   = htons(g_options.port_num);
    in_addr->sin_addr   = *(struct in_addr*)he->h_addr_list[0];
    return 0;
}

static int init_dc_qps(struct rdma_cm_id *rdma_cm_id)
{
    struct ibv_exp_qp_init_attr qp_init_attr;
    struct ibv_exp_dct_init_attr dct_attr;
    struct ibv_exp_qp_attr qp_attr;
    int i;

    if (g_test.dct) {
        return 0; /* Already initialized */
    }

    /* Create DCT
     * Note: For RoCE, must specify gid_index, hop_limit, traffic_class
     *       on command line.
     * */
    memset(&dct_attr, 0, sizeof(dct_attr));
    dct_attr.pd            = rdma_cm_id->pd;
    dct_attr.cq            = g_test.cq;
    dct_attr.srq           = g_test.srq;
    dct_attr.dc_key        = DC_KEY;
    dct_attr.port          = rdma_cm_id->port_num;
    dct_attr.mtu           = IBV_MTU_1024; // TODO get port MTU
    dct_attr.access_flags  = MEM_ACCESS_FLAGS;
    dct_attr.min_rnr_timer = g_options.min_rnr_timer;
    dct_attr.tclass        = g_options.traffic_class;
    dct_attr.hop_limit     = g_options.hop_limit;
    dct_attr.gid_index     = g_options.gid_index;

    g_test.dct = ibv_exp_create_dct(rdma_cm_id->verbs, &dct_attr);
    if (!g_test.dct) {
        LOG_ERROR("ibv_exp_create_dct() failed: %m");
        return -1;
    }

    LOG_DEBUG("Created DCT 0x%x", g_test.dct->dct_num);

    /* Create and initialize DC initiators */
    for (i = 0; i < NUM_DCI; ++i) {
        qp_init_attr.qp_type             = IBV_EXP_QPT_DC_INI;
        qp_init_attr.send_cq             = g_test.cq;
        qp_init_attr.recv_cq             = g_test.cq;
        qp_init_attr.srq                 = g_test.srq;
        qp_init_attr.cap.max_send_wr     = g_options.tx_queue_len;
        qp_init_attr.cap.max_recv_wr     = g_options.rx_queue_len;
        qp_init_attr.cap.max_send_sge    = g_options.max_send_sge;
        qp_init_attr.cap.max_recv_sge    = g_options.max_recv_sge;
        qp_init_attr.cap.max_inline_data = sizeof(packet_t);
        qp_init_attr.sq_sig_all          = 0;
        qp_init_attr.comp_mask           = IBV_EXP_QP_INIT_ATTR_PD;
        qp_init_attr.pd                  = rdma_cm_id->pd;

        g_test.dcis[i] = ibv_exp_create_qp(rdma_cm_id->verbs, &qp_init_attr);
        if (!g_test.dcis[i]) {
            LOG_ERROR("ibv_exp_create_qp() failed: %m");
            return -1;
        }

        memset(&qp_attr, 0, sizeof(qp_attr));
        qp_attr.path_mtu           = IBV_MTU_1024; // TODO port mtu
        qp_attr.max_dest_rd_atomic = g_options.max_rd_atomic;
        qp_attr.min_rnr_timer      = g_options.min_rnr_timer;
        qp_attr.timeout            = g_options.xport_timeout;
        qp_attr.rnr_retry          = g_options.rnr_retry;
        qp_attr.retry_cnt          = g_options.xport_retry_cnt;
        qp_attr.max_rd_atomic      = g_options.max_rd_atomic;
        qp_attr.port_num           = rdma_cm_id->port_num;
        qp_attr.pkey_index         = 0;
        qp_attr.qp_access_flags    = MEM_ACCESS_FLAGS;
        qp_attr.ah_attr.is_global  = 1;
        qp_attr.ah_attr.port_num   = rdma_cm_id->port_num;
        qp_attr.rq_psn             = 0;
        qp_attr.sq_psn             = 0;
        qp_attr.dct_key            = DC_KEY;

        qp_attr.qp_state = IBV_QPS_INIT;
        int ret = ibv_exp_modify_qp(g_test.dcis[i], &qp_attr,
                                    IBV_EXP_QP_STATE      |
                                    IBV_EXP_QP_PKEY_INDEX |
                                    IBV_EXP_QP_PORT       |
                                    IBV_EXP_QP_DC_KEY);
        if (ret) {
            LOG_ERROR("ibv_exp_modify_qp(INIT) failed: %m");
            return -1;
        }

        qp_attr.qp_state = IBV_QPS_RTR;
        ret = ibv_exp_modify_qp(g_test.dcis[i], &qp_attr,
                                IBV_EXP_QP_STATE    |
                                IBV_EXP_QP_PATH_MTU |
                                IBV_EXP_QP_AV);
        if (ret) {
            LOG_ERROR("ibv_exp_modify_qp(RTR) failed: %m");
            return -1;
        }

        qp_attr.qp_state = IBV_QPS_RTS;
        ret = ibv_exp_modify_qp(g_test.dcis[i], &qp_attr,
                                IBV_EXP_QP_STATE      |
                                IBV_EXP_QP_TIMEOUT    |
                                IBV_EXP_QP_RETRY_CNT  |
                                IBV_EXP_QP_RNR_RETRY  |
                                IBV_EXP_QP_MAX_QP_RD_ATOMIC);
        if (ret) {
            LOG_ERROR("ibv_exp_modify_qp(RTS) failed: %m");
            return -1;
        }

        LOG_DEBUG("Created DCI[%d]=0x%x", i, g_test.dcis[i]->qp_num);
    }

    return 0;
}

static int post_receives()
{
    struct ibv_recv_wr wr, *bad_wr;
    struct ibv_sge sge;
    unsigned i;
    void *ptr;
    int ret;

    /* We post receives only once, should have enough to handle 2 control
     * message for every connection (SYN,FIN)
     */
    for (i = 0; i < g_test.recv_available; ++i) {
        /* sge.addr points to grh, wr_id points after grh */
        ptr        = g_test.recv_buf.ptr +
                     i * (sizeof(packet_t) + g_test.grh_size);
        wr.next    = NULL;
        wr.num_sge = 1;
        wr.sg_list = &sge;
        sge.addr   = (uintptr_t)ptr;
        sge.length = sizeof(packet_t);
        sge.lkey   = g_test.recv_buf.mr->lkey;
        wr.wr_id   = (uintptr_t)ptr + g_test.grh_size;

        ret = ibv_post_srq_recv(g_test.srq, &wr, &bad_wr);
        if (ret) {
            LOG_ERROR("ibv_post_srq_recv() failed: %m");
            return ret;
        }
    }

    if (g_test.recv_available) {
        LOG_DEBUG("Posted %d receives", g_test.recv_available);
        g_test.recv_available = 0;
    }

    return 0;
}

static int init_transport(struct rdma_cm_id *rdma_cm_id)
{
    struct ibv_srq_init_attr srq_init_attr;
    struct ibv_qp_init_attr qp_init_attr;
    int ret;

    if (!g_test.cq) {
        /* Create single completion queue for both sends and receives */
        g_test.cq = ibv_create_cq(rdma_cm_id->verbs,
                                   g_options.tx_queue_len + g_options.rx_queue_len, /* cqe */
                                   NULL, /* cq_context */
                                   NULL, /* comp_channel */
                                   0  /* comp_vector */ );
        if (!g_test.cq) {
            LOG_ERROR("ibv_create_cq() failed: %m");
            return -1;
        }

        LOG_DEBUG("Created CQ @%p", g_test.cq)
    }

    if (!g_test.srq) {
        /* Create a shared receive queue for control messages */
        srq_init_attr.srq_context    = NULL;
        srq_init_attr.attr.max_wr    = g_options.rx_queue_len;
        srq_init_attr.attr.max_sge   = g_options.max_recv_sge;
        srq_init_attr.attr.srq_limit = 0;
        g_test.srq = ibv_create_srq(rdma_cm_id->pd, &srq_init_attr);
        if (!g_test.srq) {
            LOG_ERROR("ibv_create_srq() failed: %m");
            return -1;
        }

        g_test.recv_available = g_options.rx_queue_len;

        LOG_DEBUG("Created SRQ @%p", g_test.srq);
    }

    /* Create buffer for receives */
    ret = init_buffer(rdma_cm_id->pd, g_options.rx_queue_len * sizeof(packet_t),
                      &g_test.recv_buf);
    if (ret) {
        return ret;
    }

    /* Create buffer for RDMA (one buffer which is split between connections) */
    ret = init_buffer(rdma_cm_id->pd,
                      g_options.num_connections * g_options.rdma_read_size,
                      &g_test.rdma_buf);
    if (ret) {
        return ret;
    }

    ret = post_receives();
    if (ret) {
        return ret;
    }

    if (g_options.transport == XPORT_RC) {
        /* Create RC QP for the connection */
        memset(&qp_init_attr, 0, sizeof(qp_init_attr));
        qp_init_attr.qp_type             = IBV_QPT_RC;
        qp_init_attr.send_cq             = g_test.cq;
        qp_init_attr.recv_cq             = g_test.cq;
        qp_init_attr.srq                 = g_test.srq;
        qp_init_attr.cap.max_send_wr     = g_options.tx_queue_len;
        qp_init_attr.cap.max_recv_wr     = g_options.rx_queue_len;
        qp_init_attr.cap.max_send_sge    = g_options.max_send_sge;
        qp_init_attr.cap.max_recv_sge    = g_options.max_recv_sge;
        qp_init_attr.cap.max_inline_data = 0;
        qp_init_attr.sq_sig_all          = 0;

        ret = rdma_create_qp(rdma_cm_id, rdma_cm_id->pd, &qp_init_attr);
        if (ret) {
            LOG_ERROR("rdma_create_qp() failed: %m");
            return ret;
        }

        LOG_DEBUG("Created RC QP 0x%x", rdma_cm_id->qp->qp_num);
    } else if (g_options.transport == XPORT_DC) {
        /* Initialize DC objects (done only once) */
        ret = init_dc_qps(rdma_cm_id);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static connection_t* add_connection(struct rdma_cm_id *rdma_cm_id)
{
    connection_t *conn;

    conn = &g_test.conns[g_test.num_conns++];
    conn->rdma_id = rdma_cm_id;
    return conn;
}

static void get_conn_param(struct rdma_conn_param *conn_param,
                           conn_priv_t *priv, unsigned conn_index)
{
    priv->conn_index          = conn_index;
    priv->rkey                = g_test.rdma_buf.mr->rkey;
    priv->virt_addr           = (uint64_t)g_test.rdma_buf.ptr +
                                (conn_index * g_options.rdma_read_size);
    if (g_options.transport == XPORT_DC) {
        priv->dct_num         = g_test.dct->dct_num;
    }

    conn_param->private_data        = priv;
    conn_param->private_data_len    = sizeof(*priv);
    conn_param->responder_resources = g_options.max_rd_atomic;
    conn_param->initiator_depth     = g_options.max_rd_atomic;
    conn_param->retry_count         = g_options.xport_retry_cnt;
    conn_param->rnr_retry_count     = g_options.rnr_retry;
}

static void set_conn_param(const struct rdma_conn_param *conn_param,
                           connection_t *conn)
{
    const conn_priv_t *remote_priv = conn_param->private_data;

    conn->remote_dctn = remote_priv->dct_num;
    conn->remote_addr = remote_priv->virt_addr;
    conn->rkey        = remote_priv->rkey;
}

static int handle_connect_request(struct rdma_cm_event *event)
{
    struct rdma_conn_param conn_param;
    conn_priv_t priv;
    connection_t *conn;
    int ret;

    ret = init_transport(event->id);
    if (ret) {
        return ret;
    }

    /* add a new connection and set its parameters according to private_data
     * received from the client
     */
    conn = add_connection(event->id);
    set_conn_param(&event->param.conn, conn);

    /* send accept message to the client with our own parameters in private_data */
    memset(&conn_param, 0, sizeof conn_param);
    get_conn_param(&conn_param, &priv, conn - g_test.conns);
    ret = rdma_accept(event->id, &conn_param);
    if (ret) {
        LOG_ERROR("rdma_accept() failed: %m");
        return -1;
    }

    return 0;
}

static int is_client()
{
    return strlen(g_options.dest_address);
}

/* send control message (SYN or FIN) */
static int send_control(connection_t *conn, enum packet_type type,
                        unsigned conn_index)
{
    packet_t packet = { .type = type,
                        .conn_index = conn_index };
    struct ibv_exp_send_wr exp_wr, *bad_exp_wr;
    struct ibv_send_wr wr, *bad_wr;
    struct ibv_sge sge;
    int ret;

    sge.addr   = (uintptr_t)&packet;
    sge.length = sizeof(packet);
    sge.lkey   = 0;

    if (g_options.transport == XPORT_DC) {
        memset(&exp_wr, 0, sizeof(exp_wr));
        exp_wr.sg_list           = &sge;
        exp_wr.num_sge           = 1;
        exp_wr.exp_opcode        = IBV_EXP_WR_SEND;
        exp_wr.exp_send_flags    = IBV_EXP_SEND_INLINE | IBV_EXP_SEND_SIGNALED;
        exp_wr.dc.ah             = conn->dc_ah;
        exp_wr.dc.dct_access_key = DC_KEY;
        exp_wr.dc.dct_number     = conn->remote_dctn;

        ret = ibv_exp_post_send(g_test.dcis[0], &exp_wr, &bad_exp_wr);
        if (ret) {
            LOG_ERROR("ibv_exp_post_send() failed: %m");
            return -1;
        }
    } else if (g_options.transport == XPORT_RC) {
        memset(&wr, 0, sizeof(wr));
        wr.sg_list    = &sge;
        wr.num_sge    = 1;
        wr.opcode     = IBV_WR_SEND;
        wr.send_flags = IBV_SEND_INLINE | IBV_SEND_SIGNALED;

        ret = ibv_post_send(conn->rdma_id->qp, &wr, &bad_wr);
        if (ret) {
            LOG_ERROR("ibv_post_send() failed: %m");
            return -1;
        }
    }

    LOG_TRACE("Sent packet %d conn_index %d", packet.type, packet.conn_index);
    return 0;
}

static int handle_established(struct rdma_cm_event *event)
{
    const conn_priv_t *remote_priv;
    connection_t *conn;
    int ret;

    if (is_client()) {
        /* Add new (and only) connection on client side */
        conn = add_connection(event->id);
        set_conn_param(&event->param.conn, conn);

        /* For DC transport, client copies connection parameters and creates
         * address handle
         */
        if (g_options.transport == XPORT_DC) {
            conn->dc_ah = ibv_create_ah(event->id->pd, &event->param.ud.ah_attr);
            if (!conn->dc_ah) {
                LOG_ERROR("ibv_create_ah() failed: %m");
                return -1;
            }

            LOG_DEBUG("DC ah @%p remote_dctn 0x%x", conn->dc_ah, conn->remote_dctn);
            remote_priv = event->param.conn.private_data;
            ret = send_control(conn, PACKET_SYN, remote_priv->conn_index);
            if (ret) {
                return ret;
            }
        }
    }

    ++g_test.num_established;
    return 0;
}

/* wait and process single event */
static int wait_and_process_one_event(uint64_t event_mask) {
    struct rdma_cm_event *event;
    int ret;

    ret = rdma_get_cm_event(g_test.event_ch, &event);
    if (ret) {
        LOG_ERROR("rdma_get_cm_event() failed: %m");
        return -1;
    }

    if (!(BIT(event->event) & event_mask)) {
        LOG_ERROR("Unexpected event %s", rdma_event_str(event->event));
        return -1;
    }

    LOG_DEBUG("Got rdma_cm event %s", rdma_event_str(event->event));
    switch (event->event) {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        ret = handle_connect_request(event);
        if (ret) {
            return ret;
        }
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ret = handle_established(event);
        if (ret) {
            return ret;
        }
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        ++g_test.num_disconnect;
        break;
    default:
        break;
    }

    ret = rdma_ack_cm_event(event);
    if (ret) {
        LOG_ERROR("rdma_ack_cm_event() failed: %m");
        return ret;
    }

    return 0;
}

static enum rdma_port_space get_port_space()
{
    return (g_options.transport == XPORT_RC) ? RDMA_PS_TCP : RDMA_PS_UDP;
}

static int poll_cq()
{
    connection_t *conn;
    packet_t *packet;
    struct ibv_wc wc;
    int ret;

    ret = ibv_poll_cq(g_test.cq, 1, &wc);
    if (ret < 0) {
        return ret;
    } else if (ret > 0) {
        if (wc.status != IBV_WC_SUCCESS) {
            LOG_ERROR("Completion with error: %s, vendor_err 0x%x",
                      ibv_wc_status_str(wc.status), wc.vendor_err);
            return -1;
        }

        switch (wc.opcode) {
        case IBV_WC_RECV:
            /* Packet was received */
            packet = (packet_t*)wc.wr_id;
            LOG_TRACE("Received packet %d conn_index %d at %p", packet->type,
                      packet->conn_index, packet);
            switch (packet->type) {
            case PACKET_SYN:
                if (g_options.transport == XPORT_DC) {
                    conn = &g_test.conns[packet->conn_index];
                    conn->dc_ah = ibv_create_ah_from_wc(conn->rdma_id->pd, &wc,
                                                        (void*)packet - IB_GRH_SIZE,
                                                        conn->rdma_id->port_num);
                    if (!conn->dc_ah) {
                        LOG_ERROR("ibv_create_ah_from_wc() failed: %m");
                        return -1;
                    }

                    LOG_DEBUG("Created AH @%p from WC on conn[%d]", conn->dc_ah,
                              packet->conn_index);
                    ++g_test.num_established;
                }
                break;
            case PACKET_FIN:
                ++g_test.num_fin_recvd;
            default:
                break;
            }
            break;
        case IBV_WC_SEND:
            /* Outgoing send was acknowledged on transport level */
            break;
        case IBV_WC_RDMA_READ:
            /* Outgoing RDMA_READ was completed */
            LOG_TRACE("RDMA_READ completion on connection[%ld]", wc.wr_id);
            --g_test.num_outstanding_reads;
            break;
        default:
            LOG_ERROR("Unexpected completion opcode %d", wc.opcode);
            return -1;
        }
    }
    return 0;
}

static int disconnect()
{
    unsigned i;
    int ret;

    LOG_INFO("Disconnecting %d connections", g_test.num_conns);

    /* Send FIN messages on all connections */
    for (i = 0; i < g_test.num_conns; ++i) {
        ret = send_control(&g_test.conns[i], PACKET_FIN, i);
        if (ret) {
            return ret;
        }
    }

    /* Wait for FIN messages on all connections */
    while (g_test.num_fin_recvd < g_test.num_conns) {
        ret = poll_cq();
        if (ret) {
            return ret;
        }
    }

    if (g_options.transport == XPORT_RC) {

        /* With RC, send rdma_cm disconnects on all connections */
        for (i = 0; i < g_test.num_conns; ++i) {
            ret = rdma_disconnect(g_test.conns[i].rdma_id);
            if (ret) {
                LOG_ERROR("rdma_disconnect() failed: %m");
                return ret;
            }
        }

        /* Wait for rdma_cm disconnects on all connections */
        while (g_test.num_disconnect < g_test.num_conns) {
            ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_DISCONNECTED));
            if (ret) {
                return ret;
            }
        }
    }

    return 0;
}

static int run_client()
{
    struct sockaddr_in dest_addr;
    struct rdma_conn_param conn_param;
    conn_priv_t priv;
    int ret;

    g_options.num_connections = 1;

    ret = get_address(&dest_addr);
    if (ret) {
        return ret;
    }

    LOG_INFO("Connecting to %s...", g_options.dest_address);

    ret = rdma_create_id(g_test.event_ch, &g_test.client_cm_id, NULL,
                         get_port_space());
    if (ret) {
        LOG_ERROR("rdma_create_id() failed: %m");
        return ret;
    }

    ret = rdma_resolve_addr(g_test.client_cm_id, NULL, /* src_addr */
                            (struct sockaddr *)&dest_addr,
                            g_options.conn_timeout_ms);
    if (ret) {
        LOG_ERROR("rdma_resolve_addr() failed: %m");
        return -1;
    }

    ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_ADDR_RESOLVED));
    if (ret) {
        return ret;
    }

    ret = rdma_resolve_route(g_test.client_cm_id, g_options.conn_timeout_ms);
    if (ret) {
        LOG_ERROR("rdma_resolve_route() failed: %m");
        return -1;
    }

    ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_ROUTE_RESOLVED));
    if (ret) {
        return ret;
    }

    ret = init_transport(g_test.client_cm_id);
    if (ret) {
        return ret;
    }

    memset(&conn_param, 0, sizeof conn_param);
    get_conn_param(&conn_param, &priv, 0);

    ret = rdma_connect(g_test.client_cm_id, &conn_param);
    if (ret) {
        LOG_ERROR("rdma_connect() failed: %m");
        return -1;
    }

    ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_ESTABLISHED));
    if (ret) {
        return ret;
    }

    ret = disconnect();
    if (ret) {
        return ret;
    }

    return 0;
}

static int post_rdma_read(connection_t *conn, size_t offset, size_t length)
{
    struct ibv_send_wr wr, *bad_wr;
    struct ibv_sge sge;

    sge.addr               = (uintptr_t)g_test.rdma_buf.ptr + offset;
    sge.length             = length;
    sge.lkey               = g_test.rdma_buf.mr->lkey;

    if (g_options.transport == XPORT_RC) {
        memset(&wr, 0, sizeof(wr));
        wr.wr_id               = conn - g_test.conns;
        wr.sg_list             = &sge;
        wr.num_sge             = 1;
        wr.opcode              = IBV_WR_RDMA_READ;
        wr.send_flags          = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = conn->remote_addr + offset;
        wr.wr.rdma.rkey        = conn->rkey;

        int ret = ibv_post_send(conn->rdma_id->qp, &wr, &bad_wr);
        if (ret) {
            LOG_DEBUG("ibv_post_send() failed: %m");
            return ret;
        }

        /* Update counters */
        ++g_test.num_outstanding_reads;
        conn->read_offset += length;

        LOG_TRACE("RDMA_READ on QP 0x%x remote_address 0x%lx length %u into 0x%lx",
                  conn->rdma_id->qp->qp_num, wr.wr.rdma.remote_addr, sge.length,
                  sge.addr);
    }

    /* TODO support DC */
    return 0;
}

static int do_rdma_reads()
{
    struct timeval tv_start, tv_end;
    connection_t *conn;
    double sec_elapsed;
    unsigned i, iter;
    size_t size, bytes_transferred;
    int ret;
    LIST_HEAD(sched);

    g_test.num_outstanding_reads = 0;

    /* measure the time over several iterations */
    gettimeofday(&tv_start, NULL);
    for (iter = 0; iter < g_options.num_iterations; ++iter) {
        /* insert all connections to the schedule queue */
        for (i = 0; i < g_test.num_conns; ++i) {
            g_test.conns[i].read_offset = 0;
            list_add_tail(&sched, &g_test.conns[i].list);
        }

        /* As long as not all read operations are completed, and the list is not
         * empty, continue working
         */
        while (g_test.num_outstanding_reads || !list_is_empty(&sched)) {

            /* If there are more connections with pending data, and we have not
             * exceeded the total number of outstanding reads, post the next
             * read operation
             */
            if (!list_is_empty(&sched) &&
                (g_test.num_outstanding_reads < g_options.max_outstanding_reads))
            {
                /* take the first connection from the schedule queue */
                conn = list_extract_head(&sched, connection_t, list);

                /* see how many bytes are left to read */
                size = MIN(g_options.max_read_size,
                           g_options.rdma_read_size - conn->read_offset);
                assert(size > 0);

                /* issue rdma read on the next segment */
                ret = post_rdma_read(conn, conn->read_offset, size);
                if (ret) {
                    return ret;
                }

                /* if this connection is not done, reinsert it to the tail of
                 * the schedule queue
                 */
                if (conn->read_offset < g_options.rdma_read_size) {
                    list_add_tail(&sched, &conn->list);
                }
            }

            ret = poll_cq();
            if (ret) {
                return ret;
            }
        }
    }
    gettimeofday(&tv_end, NULL);

    /* Calculate and report total read bandwidth */
    sec_elapsed = (tv_end.tv_sec - tv_start.tv_sec) +
                  (tv_end.tv_usec - tv_start.tv_usec) * 1e-6;
    bytes_transferred = g_test.num_conns * 
                        g_options.num_iterations * g_options.rdma_read_size;
    LOG_INFO("Total read bandwidth: %.2f MB/s",
             bytes_transferred / sec_elapsed / BIT(20));
    return 0;
}

static int run_server()
{
    struct sockaddr_in in_addr;
    int ret;

    /* Make TX/RX queue lengths are large enough to send/recv control messages
     * on all connections without extra CQ polling (this is done for simplicity)
     */
    g_options.rx_queue_len = MAX(g_options.rx_queue_len,
                                 g_options.num_connections * 2);
    g_options.tx_queue_len = MAX(g_options.tx_queue_len,
                                 g_options.num_connections);

    ret = rdma_create_id(g_test.event_ch, &g_test.listen_cm_id, NULL,
                         get_port_space());
    if (ret) {
        LOG_ERROR("rdma_create_id() failed: %m");
        return ret;
    }

    /* Listen on INADDR_ANY */
    memset(&in_addr, 0, sizeof(in_addr));
    in_addr.sin_family      = AF_INET;
    in_addr.sin_addr.s_addr = INADDR_ANY;
    in_addr.sin_port        = htons(g_options.port_num);
    ret = rdma_bind_addr(g_test.listen_cm_id, (struct sockaddr*)&in_addr);
    if (ret) {
        LOG_ERROR("rdma_bind_addr() failed: %m");
        return ret;
    }

    ret = rdma_listen(g_test.listen_cm_id, g_options.conn_backlog);
    if (ret) {
        LOG_ERROR("rdma_listen() failed: %m");
        return ret;
    }

    LOG_INFO("Waiting for %d connections...", g_options.num_connections);
    while (g_test.num_established < g_options.num_connections) {
        if (g_options.transport == XPORT_RC) {
            /* For RC, wait until all connections got ESTABLISHED event */
            ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_CONNECT_REQUEST) |
                                             BIT(RDMA_CM_EVENT_ESTABLISHED) |
                                             BIT(RDMA_CM_EVENT_DISCONNECTED));
            if (ret) {
                return ret;
            }
        } else if (g_options.transport == XPORT_DC) {
            /* For DC, wait until all connections got SYN packet. In meantime,
             * need to also process CONNECT_REQUEST events
             * TODO wait on CQ event / rdma event in parallel
             */
            if (g_test.num_conns < g_options.num_connections) {
                ret = wait_and_process_one_event(BIT(RDMA_CM_EVENT_CONNECT_REQUEST));
                if (ret) {
                    return ret;
                }
            }

            ret = poll_cq();
            if (ret) {
                return ret;
            }
        }
   }

    ret = do_rdma_reads();
    if (ret) {
        return ret;
    }

    ret = disconnect();
    if (ret) {
        return ret;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    ret = parse_opts(argc, argv);
    if (ret) {
        return ret;
    }

    ret = init_test();
    if (ret) {
        return ret;
    }

    if (is_client()) {
        ret = run_client();
    } else {
        ret = run_server();
    }

    cleanup_test();

    return ret;
}

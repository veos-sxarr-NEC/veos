/**
 * @file mem_xfer.h
 * @brief Read/write content in VE memory from pseudo.
 */
#ifndef mem_xfer_h
#define mem_xfer_h

int amm_dma_xfer_req(uint8_t *);
int ve_send_data(vedl_handle *, uint64_t, size_t, void *);
int ve_recv_data(vedl_handle *, uint64_t, size_t, void *);
int ve_recv_string(vedl_handle *, uint64_t, char *, size_t);
int _ve_recv_data_ipc(vedl_handle *, uint64_t, size_t, void *);
int _ve_send_data_ipc(vedl_handle *, uint64_t, size_t, void *);
int __ve_send_data(vedl_handle *, uint64_t, size_t, void *);
int __ve_recv_data(vedl_handle *, uint64_t, size_t, void *);
#endif

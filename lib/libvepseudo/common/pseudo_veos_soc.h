#ifndef VEOS_SOC_H
#define VEOS_SOC_H

extern char *veos_sock_name;

int pseudo_veos_soc(char *);
int64_t pseudo_veos_recv_cmd(int, void *, int);
ssize_t pseudo_veos_send_cmd(int, void *, int);
#endif

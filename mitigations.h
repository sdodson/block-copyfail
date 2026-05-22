#ifndef MITIGATIONS_H
#define MITIGATIONS_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define AF_ALG   38
#define AF_RXRPC 33

#define BLOCK_REASON_COPYFAIL    1
#define BLOCK_REASON_RXRPC       2
#define BLOCK_REASON_UDP_SPLICE  3
#define BLOCK_REASON_ESPINTCP    4
#define BLOCK_REASON_UDP_ENCAP   5

struct block_event {
	__u32 pid;
	char  comm[16];
	__u32 reason;
	__u64 ts;
};

#endif

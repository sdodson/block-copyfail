/* BPF LSM programs to block kernel page-cache corruption exploits.
 *
 * CopyFail (CVE-2026-31431):
 *   socket_bind — blocks AF_ALG AEAD binds (algif_aead exploit path).
 *
 * DirtyFrag:
 *   socket_create — blocks AF_RXRPC socket creation (rxrpc/rxkad path).
 *   socket_create — blocks NETLINK_XFRM from containers (xfrm-ESP path).
 *   socket_sendmsg — blocks MSG_SPLICE_PAGES on UDP sockets globally.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_copyfail.h"

/* --- CopyFail: sockaddr_alg layout for AF_ALG AEAD detection --- */

#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_CHECK_LEN 7

static const char aead_type[5] = "aead";

/* --- DirtyFrag: CO-RE struct stubs --- */

struct user_namespace {
	int level;
} __attribute__((preserve_access_index));

struct pid_namespace {
	unsigned int level;
} __attribute__((preserve_access_index));

struct cred {
	struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct task_struct {
	const struct cred *cred;
	struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	unsigned int msg_flags;
} __attribute__((preserve_access_index));

struct sockaddr;

#define AF_NETLINK        16
#define AF_INET            2
#define AF_INET6          10
#define NETLINK_XFRM       6
#define SOCK_DGRAM         2
#define MSG_SPLICE_PAGES   0x08000000

/* --- Shared ring buffer --- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

static __always_inline void emit_event(__u32 reason)
{
	struct block_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (evt) {
		evt->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(evt->comm, sizeof(evt->comm));
		evt->reason = reason;
		evt->ts = bpf_ktime_get_ns();
		bpf_ringbuf_submit(evt, 0);
	}
}

/* === CopyFail: block AF_ALG AEAD binds === */

SEC("lsm/socket_bind")
int BPF_PROG(block_copyfail, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	if (ret)
		return ret;

	if (addrlen < SOCKADDR_ALG_CHECK_LEN)
		return 0;

	__u8 buf[SOCKADDR_ALG_CHECK_LEN];

	if (bpf_probe_read_kernel(buf, sizeof(buf), address) < 0)
		return 0;

	__u16 family = *(__u16 *)&buf[0];
	if (family != AF_ALG)
		return 0;

	if (__builtin_memcmp(&buf[SOCKADDR_ALG_TYPE_OFFSET], aead_type, 5) != 0)
		return 0;

	emit_event(BLOCK_REASON_COPYFAIL);
	return -EPERM;
}

/* === DirtyFrag layer 1: block AF_RXRPC socket creation === */

SEC("lsm/socket_create")
int BPF_PROG(block_rxrpc, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	if (kern)
		return 0;

	if (family != AF_RXRPC)
		return 0;

	emit_event(BLOCK_REASON_RXRPC);
	return -EPERM;
}

/* === DirtyFrag layer 2: block NETLINK_XFRM from containers === */

SEC("lsm/socket_create")
int BPF_PROG(block_xfrm, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	if (kern)
		return 0;

	if (family != AF_NETLINK || protocol != NETLINK_XFRM)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	int level;

	level = task->cred->user_ns->level;
	if (level > 0)
		goto block;

	level = task->nsproxy->pid_ns_for_children->level;
	if (level > 0)
		goto block;

	return 0;

block:
	emit_event(BLOCK_REASON_XFRM);
	return -1;
}

/* === DirtyFrag layer 3: block MSG_SPLICE_PAGES on UDP sockets === */

SEC("lsm/socket_sendmsg")
int BPF_PROG(block_udp_splice, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;

	if (!(msg->msg_flags & MSG_SPLICE_PAGES))
		return 0;

	if (sock->type != SOCK_DGRAM)
		return 0;

	struct sock *sk = sock->sk;
	if (!sk)
		return 0;

	__u16 family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	emit_event(BLOCK_REASON_UDP_SPLICE);
	return -1;
}

char LICENSE[] SEC("license") = "GPL";

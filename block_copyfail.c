#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "block_copyfail.h"
#include "block_copyfail.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

struct mitigation_flags {
	int copyfail;
	int rxrpc;
	int xfrm;
	int udp_splice;
};

static void parse_mitigations(struct mitigation_flags *f)
{
	const char *env = getenv("MITIGATIONS");

	if (!env || !*env || strcmp(env, "all") == 0) {
		f->copyfail = f->rxrpc = f->xfrm = f->udp_splice = 1;
		return;
	}

	f->copyfail = f->rxrpc = f->xfrm = f->udp_splice = 0;

	char buf[256];
	strncpy(buf, env, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
		while (*tok == ' ') tok++;
		if (strcmp(tok, "all") == 0) {
			f->copyfail = f->rxrpc = f->xfrm = f->udp_splice = 1;
		} else if (strcmp(tok, "copyfail") == 0) {
			f->copyfail = 1;
		} else if (strcmp(tok, "dirtyfrag") == 0) {
			f->rxrpc = f->xfrm = f->udp_splice = 1;
		} else if (strcmp(tok, "rxrpc") == 0) {
			f->rxrpc = 1;
		} else if (strcmp(tok, "xfrm") == 0) {
			f->xfrm = 1;
		} else if (strcmp(tok, "udp_splice") == 0) {
			f->udp_splice = 1;
		} else {
			fprintf(stderr, "block-copyfail: unknown mitigation '%s', ignoring\n", tok);
		}
	}
}

static __u64 boot_time_ns;

static int handle_event(void *ctx, void *data, size_t len)
{
	if (len < sizeof(struct block_event))
		return 0;

	struct block_event *evt = data;
	time_t event_sec = (evt->ts + boot_time_ns) / 1000000000ULL;
	struct tm *tm = localtime(&event_sec);
	char ts[32];
	const char *what;

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	switch (evt->reason) {
	case BLOCK_REASON_COPYFAIL:   what = "AF_ALG AEAD bind";      break;
	case BLOCK_REASON_RXRPC:      what = "AF_RXRPC socket";       break;
	case BLOCK_REASON_XFRM:       what = "XFRM from container";   break;
	case BLOCK_REASON_UDP_SPLICE: what = "UDP MSG_SPLICE_PAGES";  break;
	default:                      what = "unknown";               break;
	}
	fprintf(stderr, "block-copyfail: BLOCKED %s pid=%-8u comm=%.*s time=%s\n",
		what, evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct block_copyfail_bpf *skel;
	struct ring_buffer *rb;
	struct mitigation_flags flags;

	parse_mitigations(&flags);

	if (!flags.copyfail && !flags.rxrpc && !flags.xfrm && !flags.udp_splice) {
		fprintf(stderr, "block-copyfail: no mitigations enabled, exiting\n");
		return 1;
	}

	skel = block_copyfail_bpf__open();
	if (!skel) {
		fprintf(stderr, "block-copyfail: failed to open BPF skeleton\n");
		return 1;
	}

	if (!flags.copyfail)
		bpf_program__set_autoattach(skel->progs.block_copyfail, false);
	if (!flags.rxrpc)
		bpf_program__set_autoattach(skel->progs.block_rxrpc, false);
	if (!flags.xfrm)
		bpf_program__set_autoattach(skel->progs.block_xfrm, false);
	if (!flags.udp_splice)
		bpf_program__set_autoattach(skel->progs.block_udp_splice, false);

	if (block_copyfail_bpf__load(skel)) {
		fprintf(stderr, "block-copyfail: failed to load BPF programs\n");
		block_copyfail_bpf__destroy(skel);
		return 1;
	}

	if (block_copyfail_bpf__attach(skel)) {
		fprintf(stderr, "block-copyfail: failed to attach BPF programs\n");
		block_copyfail_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "block-copyfail: active mitigations:");
	if (flags.copyfail)   fprintf(stderr, " copyfail");
	if (flags.rxrpc)      fprintf(stderr, " rxrpc");
	if (flags.xfrm)       fprintf(stderr, " xfrm");
	if (flags.udp_splice) fprintf(stderr, " udp_splice");
	fprintf(stderr, "\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "block-copyfail: failed to create ring buffer\n");
		block_copyfail_bpf__destroy(skel);
		return 1;
	}

	struct timespec rt, bt;
	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	boot_time_ns = (__u64)rt.tv_sec * 1000000000ULL + rt.tv_nsec
		     - (__u64)bt.tv_sec * 1000000000ULL - bt.tv_nsec;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "block-copyfail: detaching\n");
	ring_buffer__free(rb);
	block_copyfail_bpf__destroy(skel);
	return 0;
}

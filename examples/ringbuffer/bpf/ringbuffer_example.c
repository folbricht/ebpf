#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	char comm[16];
	char filename[256];
};

struct syscall_enter_args {
	unsigned long long common_tp_fields;
	long               syscall_nr;
	unsigned long      args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256KB */);
} events SEC(".maps");

SEC("tracepoint/sys_enter_openat")
int tp_syscall_sys_enter_openat(struct syscall_enter_args *args) {
	struct event_t *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const void *)args->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

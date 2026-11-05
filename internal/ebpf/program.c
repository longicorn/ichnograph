//go:build ignore
#include <linux/bpf.h>
#include <linux/types.h>
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*ktime)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*read_str)(void *, __u32, const void *) = (void *)BPF_FUNC_probe_read_user_str;
static void *(*reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } tracked SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } lost SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } retry_paths SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } mmap_pending SEC(".maps");
struct event { __u64 ns; __u32 pid, tid; __s32 dirfd; __s32 path_result; __u32 kind; char path[256]; };
struct syscall_enter { __u64 common; long id; unsigned long args[6]; };
struct syscall_exit { __u64 common; long id; long ret; };
struct fork_ctx { __u64 common; char parent_comm[16]; __s32 parent_pid; char child_comm[16]; __s32 child_pid; };
struct exec_ctx { __u64 common; __u32 filename; __s32 pid; __s32 old_pid; };
SEC("tracepoint/sched/sched_process_fork") int fork_event(struct fork_ctx *ctx) {
 __u32 parent = ctx->parent_pid, child = ctx->child_pid, one = 1, zero = 0;
 if (map_lookup(&tracked, &parent) && map_update(&tracked, &child, &one, BPF_ANY)) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); }
 return 0;
}
SEC("tracepoint/sched/sched_process_exit") int exit_event(void *ctx) { __u32 tid = (__u32)pid_tgid(); map_delete(&tracked, &tid); map_delete(&retry_paths, &tid); map_delete(&mmap_pending, &tid); return 0; }
SEC("tracepoint/sched/sched_process_exec") int exec_transition(struct exec_ctx *ctx) {
 __u32 old = ctx->old_pid, current = ctx->pid, zero = 0, one = 1;
 if (!map_lookup(&tracked, &old)) return 0;
 if (old != current) {
  if (map_update(&tracked, &current, &one, BPF_ANY)) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
  map_delete(&tracked, &old); map_delete(&retry_paths, &old); map_delete(&mmap_pending, &old);
 }
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = current; e->dirfd = old; e->kind = 9; submit(e, 0); return 0;
}
static __attribute__((always_inline)) inline int handle_openat(struct syscall_enter *ctx, int dirfd, __u64 pathname, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 map_delete(&retry_paths, &tid);
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { map_delete(&retry_paths, &tid); __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = dirfd; e->kind = kind;
 __builtin_memset(e->path, 0, sizeof(e->path));
 e->path_result = read_str(e->path, sizeof(e->path), (void *)pathname);
 if (e->path_result < 0) { __u64 ptr = pathname; if (map_update(&retry_paths, &tid, &ptr, BPF_ANY)) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); } }
 submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat") int openat_event(struct syscall_enter *ctx) { return handle_openat(ctx, ctx->args[0], ctx->args[1], 0); }
SEC("tracepoint/syscalls/sys_enter_openat2") int openat2_event(struct syscall_enter *ctx) { return handle_openat(ctx, ctx->args[0], ctx->args[1], 10); }
SEC("tracepoint/syscalls/sys_enter_open") int open_event(struct syscall_enter *ctx) { return handle_openat(ctx, -100, ctx->args[0], 11); }
SEC("tracepoint/syscalls/sys_enter_creat") int creat_event(struct syscall_enter *ctx) { return handle_openat(ctx, -100, ctx->args[0], 12); }
static __attribute__((always_inline)) inline int handle_openat_exit(struct syscall_exit *ctx, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { map_delete(&retry_paths, &tid); __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = tid; e->dirfd = ctx->ret; e->kind = kind;
 __u64 *ptr = map_lookup(&retry_paths, &tid);
 if (ptr) { if ((kind != 7 && kind != 8) || ctx->ret < 0) e->path_result = read_str(e->path, sizeof(e->path), (void *)*ptr); map_delete(&retry_paths, &tid); }
 submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_exit_openat") int openat_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 0); }
SEC("tracepoint/syscalls/sys_exit_openat2") int openat2_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 10); }
SEC("tracepoint/syscalls/sys_exit_open") int open_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 11); }
SEC("tracepoint/syscalls/sys_exit_creat") int creat_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 12); }
SEC("tracepoint/syscalls/sys_enter_execve") int execve_event(struct syscall_enter *ctx) { return handle_openat(ctx, -100, ctx->args[0], 7); }
SEC("tracepoint/syscalls/sys_enter_execveat") int execveat_event(struct syscall_enter *ctx) { return handle_openat(ctx, ctx->args[0], ctx->args[1], 8); }
SEC("tracepoint/syscalls/sys_exit_execve") int execve_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 7); }
SEC("tracepoint/syscalls/sys_exit_execveat") int execveat_exit(struct syscall_exit *ctx) { return handle_openat_exit(ctx, 8); }
static __attribute__((always_inline)) inline int handle_read(struct syscall_enter *ctx, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = ctx->args[0]; e->kind = kind; submit(e, 0); return 0;
}
static __attribute__((always_inline)) inline int handle_read_exit(struct syscall_exit *ctx, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = tid; e->dirfd = ctx->ret; e->kind = kind; submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_enter_read") int read_event(struct syscall_enter *ctx) { return handle_read(ctx, 1); }
SEC("tracepoint/syscalls/sys_exit_read") int read_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 1); }
SEC("tracepoint/syscalls/sys_enter_pread64") int pread_event(struct syscall_enter *ctx) { return handle_read(ctx, 2); }
SEC("tracepoint/syscalls/sys_exit_pread64") int pread_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 2); }
SEC("tracepoint/syscalls/sys_enter_readv") int readv_event(struct syscall_enter *ctx) { return handle_read(ctx, 3); }
SEC("tracepoint/syscalls/sys_exit_readv") int readv_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 3); }
SEC("tracepoint/syscalls/sys_enter_preadv") int preadv_event(struct syscall_enter *ctx) { return handle_read(ctx, 4); }
SEC("tracepoint/syscalls/sys_exit_preadv") int preadv_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 4); }
SEC("tracepoint/syscalls/sys_enter_preadv2") int preadv2_event(struct syscall_enter *ctx) { return handle_read(ctx, 5); }
SEC("tracepoint/syscalls/sys_exit_preadv2") int preadv2_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 5); }
SEC("tracepoint/syscalls/sys_enter_write") int write_event(struct syscall_enter *ctx) { return handle_read(ctx, 13); }
SEC("tracepoint/syscalls/sys_exit_write") int write_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 13); }
SEC("tracepoint/syscalls/sys_enter_pwrite64") int pwrite_event(struct syscall_enter *ctx) { return handle_read(ctx, 14); }
SEC("tracepoint/syscalls/sys_exit_pwrite64") int pwrite_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 14); }
SEC("tracepoint/syscalls/sys_enter_writev") int writev_event(struct syscall_enter *ctx) { return handle_read(ctx, 15); }
SEC("tracepoint/syscalls/sys_exit_writev") int writev_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 15); }
SEC("tracepoint/syscalls/sys_enter_pwritev") int pwritev_event(struct syscall_enter *ctx) { return handle_read(ctx, 16); }
SEC("tracepoint/syscalls/sys_exit_pwritev") int pwritev_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 16); }
SEC("tracepoint/syscalls/sys_enter_pwritev2") int pwritev2_event(struct syscall_enter *ctx) { return handle_read(ctx, 17); }
SEC("tracepoint/syscalls/sys_exit_pwritev2") int pwritev2_exit(struct syscall_exit *ctx) { return handle_read_exit(ctx, 17); }
SEC("tracepoint/syscalls/sys_enter_mmap") int mmap_event(struct syscall_enter *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 // Anonymous mappings do not refer to a file descriptor.
 if (ctx->args[3] & 0x20) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __u32 one = 1; if (map_update(&mmap_pending, &tid, &one, BPF_ANY)) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); }
 __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = ctx->args[4]; e->kind = 6; submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_exit_mmap") int mmap_exit(struct syscall_exit *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 if (!map_lookup(&mmap_pending, &tid)) return 0;
 map_delete(&mmap_pending, &tid);
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { __u64 *n = map_lookup(&lost, &zero); if (n) __sync_fetch_and_add(n, 1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = tid; e->ns = ctx->ret; e->kind = 6; submit(e, 0); return 0;
}
char LICENSE[] SEC("license") = "GPL";

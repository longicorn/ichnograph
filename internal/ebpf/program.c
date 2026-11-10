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
static long (*read_user)(void *, __u32, const void *) = (void *)BPF_FUNC_probe_read_user;
static long (*read_str)(void *, __u32, const void *) = (void *)BPF_FUNC_probe_read_user_str;
static void *(*reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
static void (*discard)(void *, __u64) = (void *)BPF_FUNC_ringbuf_discard;
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } tracked SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 7); __type(key, __u32); __type(value, __u64); } lost SEC(".maps");
static __always_inline void count_loss(__u32 kind) { __u32 total = 0; __u64 *n = map_lookup(&lost, &total); if (n) __sync_fetch_and_add(n, 1); n = map_lookup(&lost, &kind); if (n) __sync_fetch_and_add(n, 1); }
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } retry_paths SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } mmap_pending SEC(".maps");
// CO-RE reads only the fields needed to recognize inherited pipes.
struct super_block { unsigned int s_dev; unsigned long s_magic; } __attribute__((preserve_access_index));
struct inode { unsigned short i_mode; unsigned int i_rdev; unsigned long i_ino; unsigned int i_generation; struct super_block *i_sb; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; void *private_data; } __attribute__((preserve_access_index));
struct fdtable { unsigned int max_fds; struct file **fd; } __attribute__((preserve_access_index));
struct files_struct { struct fdtable *fdt; } __attribute__((preserve_access_index));
struct task_struct { struct files_struct *files; struct task_struct *group_leader; unsigned long long start_boottime; } __attribute__((preserve_access_index));
static void *(*current_task)(void) = (void *)BPF_FUNC_get_current_task;
static long (*read_kernel)(void *, __u32, const void *) = (void *)BPF_FUNC_probe_read_kernel;
#define READ_FIELD(dst, ptr, field) read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(ptr)->field))
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } suppressed_io SEC(".maps");
static __always_inline int ignored_io(int fd) {
 if (fd < 0) return 0;
 struct task_struct *task = current_task(); struct files_struct *files = 0; struct fdtable *table = 0;
 struct file **fds = 0; struct file *file = 0; struct inode *inode = 0; unsigned int max = 0; unsigned short mode = 0;
 if (READ_FIELD(files, task, files) || !files || READ_FIELD(table, files, fdt) || !table ||
     READ_FIELD(max, table, max_fds) || (__u32)fd >= max || READ_FIELD(fds, table, fd) || !fds ||
     read_kernel(&file, sizeof(file), &fds[fd]) || !file || READ_FIELD(inode, file, f_inode) || !inode ||
     READ_FIELD(mode, inode, i_mode)) return 0;
 if ((mode & 0170000) == 0010000) return fd <= 2;
 if ((mode & 0170000) != 0020000) return 0;
 unsigned int device = 0;
 if (READ_FIELD(device, inode, i_rdev)) return 0;
 unsigned int major = device >> 20, minor = device & ((1U << 20) - 1);
 // Fixed pseudo-devices and Linux virtual terminals, serial ttys, console and PTYs.
 return (major == 1 && (minor == 3 || minor == 5 || minor == 7 || minor == 8 || minor == 9)) || major == 4 || (major == 5 && minor <= 2) || (major >= 136 && major <= 143);
}
// Regular-file identity is shared by duplicated and inherited descriptors.
struct read_identity { __u64 ino; __u64 process_start; __u32 dev; __u32 pid; __u32 generation; __u32 padding; };
struct write_pending_value { __u64 ns; __s32 fd; __u32 regular; struct read_identity identity; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct write_pending_value); } write_pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct read_identity); __type(value, __u32); } write_seen SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct read_identity); __type(value, __u64); } write_retry SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct read_identity); __type(value, __u32); } read_seen SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct read_identity); __type(value, __u64); } read_retry SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct read_identity); } read_pending SEC(".maps");
static __always_inline int regular_identity(int fd, __u32 pid, struct read_identity *key) {
 if (fd < 0) return 0;
 struct task_struct *task = current_task(); struct files_struct *files = 0; struct fdtable *table = 0;
 struct file **fds = 0; struct file *file = 0; struct inode *inode = 0; struct super_block *sb = 0;
 unsigned int max = 0, dev = 0, generation = 0; unsigned short mode = 0; unsigned long ino = 0;
 struct task_struct *leader = 0; __u64 process_start = 0;
 if (!__builtin_preserve_field_info(task->start_boottime, 2)) return 0;
 if (READ_FIELD(leader, task, group_leader) || !leader || READ_FIELD(process_start, leader, start_boottime)) return 0;
 if (READ_FIELD(files, task, files) || !files || READ_FIELD(table, files, fdt) || !table ||
 READ_FIELD(max, table, max_fds) || (__u32)fd >= max || READ_FIELD(fds, table, fd) || !fds ||
 read_kernel(&file, sizeof(file), &fds[fd]) || !file || READ_FIELD(inode, file, f_inode) || !inode ||
 READ_FIELD(mode, inode, i_mode) || (mode & 0170000) != 0100000 || READ_FIELD(ino, inode, i_ino) ||
 READ_FIELD(sb, inode, i_sb) || !sb || READ_FIELD(dev, sb, s_dev)) return 0;
 if (__builtin_preserve_field_info(inode->i_generation, 2)) { if (READ_FIELD(generation, inode, i_generation)) return 0; }
 key->ino = ino; key->dev = dev; key->pid = pid; key->generation = generation; key->process_start = process_start; return 1;
}
struct socket { short type; void *sk; } __attribute__((preserve_access_index));
static __always_inline unsigned short socket_type(int fd) {
 if (fd < 0 || !__builtin_preserve_field_info(((struct socket *)0)->type, 2)) return 0;
 struct task_struct *task = current_task(); struct files_struct *files = 0; struct fdtable *table = 0;
 struct file **fds = 0; struct file *file = 0; struct inode *inode = 0; struct socket *socket = 0;
 unsigned int max = 0; unsigned short mode = 0, type = 0;
 if (READ_FIELD(files, task, files) || !files || READ_FIELD(table, files, fdt) || !table ||
 READ_FIELD(max, table, max_fds) || (__u32)fd >= max || READ_FIELD(fds, table, fd) || !fds ||
 read_kernel(&file, sizeof(file), &fds[fd]) || !file || READ_FIELD(inode, file, f_inode) || !inode ||
 READ_FIELD(mode, inode, i_mode) || (mode & 0170000) != 0140000 ||
 READ_FIELD(socket, file, private_data) || !socket || READ_FIELD(type, socket, type)) return 0;
 return type;
}
// The socket pointer stays in kernel maps; userspace receives only an opaque token.
struct tcp_track { __u64 token; __u32 pid, tid; };
struct tcp_tid { __u64 sk; __u64 token; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, struct tcp_track); } tcp_connects SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct tcp_tid); } tcp_entered SEC(".maps");
static __always_inline __u64 socket_sock(int fd) {
 if (fd < 0 || !__builtin_preserve_field_info(((struct socket *)0)->sk, 2)) return 0;
 struct task_struct *task = current_task(); struct files_struct *files = 0; struct fdtable *table = 0;
 struct file **fds = 0; struct file *file = 0; struct inode *inode = 0; struct socket *socket = 0; void *sk = 0; unsigned int max = 0; unsigned short mode = 0;
 if (READ_FIELD(files, task, files) || !files || READ_FIELD(table, files, fdt) || !table || READ_FIELD(max, table, max_fds) || (__u32)fd >= max ||
 READ_FIELD(fds, table, fd) || !fds || read_kernel(&file, sizeof(file), &fds[fd]) || !file || READ_FIELD(inode, file, f_inode) || !inode ||
 READ_FIELD(mode, inode, i_mode) || (mode & 0170000) != 0140000 || READ_FIELD(socket, file, private_data) || !socket || READ_FIELD(sk, socket, sk)) return 0;
 return (__u64)sk;
}
struct event { __u64 ns; __u32 pid, tid; __s32 dirfd; __s32 path_result; __u32 kind; char path[256]; };
struct fd_event { __u64 ns; __u32 pid, tid; __s32 dirfd; __s32 path_result; __u32 kind; struct read_identity identity; };
struct pipe_key { __u64 process_start; __u32 pid, kind, direction, padding; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct pipe_key); __type(value, __u32); } pipe_seen SEC(".maps");
static __always_inline void observe_pipe(int fd, __u32 direction) {
 if (fd < 0) return;
 __u64 id = pid_tgid(); struct task_struct *task = current_task(), *leader = 0;
 struct files_struct *files = 0; struct fdtable *table = 0; struct file **fds = 0, *file = 0;
 struct inode *inode = 0; struct super_block *sb = 0; unsigned int max = 0; unsigned short mode = 0; unsigned long magic = 0;
 if (READ_FIELD(files, task, files) || !files || READ_FIELD(table, files, fdt) || !table ||
 READ_FIELD(max, table, max_fds) || (__u32)fd >= max || READ_FIELD(fds, table, fd) || !fds ||
 read_kernel(&file, sizeof(file), &fds[fd]) || !file || READ_FIELD(inode, file, f_inode) || !inode ||
 READ_FIELD(mode, inode, i_mode) || (mode & 0170000) != 0010000 || READ_FIELD(sb, inode, i_sb) || !sb || READ_FIELD(magic, sb, s_magic)) return;
 struct pipe_key key = {}; key.pid = id >> 32; key.kind = magic == 0x50495045UL ? 21 : 20; key.direction = direction;
 if (__builtin_preserve_field_info(task->start_boottime, 2) && !READ_FIELD(leader, task, group_leader) && leader) READ_FIELD(key.process_start, leader, start_boottime);
 if (key.process_start && map_lookup(&pipe_seen, &key)) return;
 struct fd_event *e = reserve(&events, sizeof(*e), 0); if (!e) { count_loss(1); return; }
 if (key.process_start) { __u32 one = 1; if (map_update(&pipe_seen, &key, &one, BPF_NOEXIST) && map_lookup(&pipe_seen, &key)) { discard(e, 0); return; } }
 __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = id >> 32; e->tid = (__u32)id; e->dirfd = fd; e->path_result = direction; e->kind = key.kind; submit(e, 0);
}
struct syscall_enter { __u64 common; long id; unsigned long args[6]; };
struct syscall_exit { __u64 common; long id; long ret; };
struct tcp_state_ctx { __u64 common, sk; __s32 oldstate, newstate; __u16 sport, dport, family, protocol; };
struct fork_ctx { __u64 common; char parent_comm[16]; __s32 parent_pid; char child_comm[16]; __s32 child_pid; };
struct exec_ctx { __u64 common; __u32 filename; __s32 pid; __s32 old_pid; };
SEC("tracepoint/sched/sched_process_fork") int fork_event(struct fork_ctx *ctx) {
 __u32 parent = ctx->parent_pid, child = ctx->child_pid, one = 1, zero = 0;
 if (map_lookup(&tracked, &parent) && map_update(&tracked, &child, &one, BPF_ANY)) { count_loss(2); }
 return 0;
}
SEC("tracepoint/sched/sched_process_exit") int exit_event(void *ctx) { __u32 tid = (__u32)pid_tgid(); map_delete(&tracked, &tid); map_delete(&retry_paths, &tid); map_delete(&mmap_pending, &tid); map_delete(&suppressed_io, &tid); map_delete(&write_pending, &tid); map_delete(&read_pending, &tid); map_delete(&tcp_entered, &tid); return 0; }
SEC("tracepoint/sched/sched_process_exec") int exec_transition(struct exec_ctx *ctx) {
 __u32 old = ctx->old_pid, current = ctx->pid, zero = 0, one = 1;
 if (!map_lookup(&tracked, &old)) return 0;
 if (old != current) {
  if (map_update(&tracked, &current, &one, BPF_ANY)) { count_loss(2); return 0; }
  map_delete(&tracked, &old); map_delete(&retry_paths, &old); map_delete(&mmap_pending, &old);
 }
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { count_loss(1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = current; e->dirfd = old; e->kind = 9; submit(e, 0); return 0;
}
static __attribute__((always_inline)) inline int handle_openat(struct syscall_enter *ctx, int dirfd, __u64 pathname, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 map_delete(&retry_paths, &tid);
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { map_delete(&retry_paths, &tid); count_loss(1); return 0; }
 e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = dirfd; e->kind = kind;
 __builtin_memset(e->path, 0, sizeof(e->path));
 e->path_result = read_str(e->path, sizeof(e->path), (void *)pathname);
 if (e->path_result < 0) { __u64 ptr = pathname; if (map_update(&retry_paths, &tid, &ptr, BPF_ANY)) { count_loss(3); } }
 submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat") int openat_event(struct syscall_enter *ctx) { return handle_openat(ctx, ctx->args[0], ctx->args[1], 0); }
SEC("tracepoint/syscalls/sys_enter_openat2") int openat2_event(struct syscall_enter *ctx) { return handle_openat(ctx, ctx->args[0], ctx->args[1], 10); }
SEC("tracepoint/syscalls/sys_enter_open") int open_event(struct syscall_enter *ctx) { return handle_openat(ctx, -100, ctx->args[0], 11); }
SEC("tracepoint/syscalls/sys_enter_creat") int creat_event(struct syscall_enter *ctx) { return handle_openat(ctx, -100, ctx->args[0], 12); }
static __attribute__((always_inline)) inline int handle_openat_exit(struct syscall_exit *ctx, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { map_delete(&retry_paths, &tid); count_loss(1); return 0; }
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
 map_delete(&suppressed_io, &tid);
 map_delete(&read_pending, &tid);

 observe_pipe((int)ctx->args[0], 1);
 if (ignored_io((int)ctx->args[0])) { __u32 one = 1; if (!map_update(&suppressed_io, &tid, &one, BPF_ANY)) return 0; }
 struct read_identity key = {};
 int regular = regular_identity((int)ctx->args[0], id >> 32, &key);
 if (regular && map_lookup(&read_seen, &key)) { __u32 one = 1; if (!map_update(&suppressed_io, &tid, &one, BPF_ANY)) return 0; }
 __u64 now = ktime();
 if (regular) {
  __u64 *last = map_lookup(&read_retry, &key);
  if (last && now >= *last && now - *last < 100000000ULL) { __u32 one = 1; if (!map_update(&suppressed_io, &tid, &one, BPF_ANY)) return 0; }
 }
 struct fd_event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { count_loss(1); return 0; }
 if (regular) map_update(&read_pending, &tid, &key, BPF_ANY);
 __builtin_memset(e, 0, sizeof(*e)); if (regular) e->identity = key; e->ns = now; e->pid = id >> 32; e->tid = tid; e->dirfd = ctx->args[0]; e->kind = kind; submit(e, 0); return 0;
}
static __attribute__((always_inline)) inline int handle_read_exit(struct syscall_exit *ctx, __u32 kind) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 if (map_lookup(&suppressed_io, &tid)) { map_delete(&suppressed_io, &tid); return 0; }
 struct fd_event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { count_loss(1); return 0; }

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
static __always_inline int handle_write(struct syscall_enter *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id; if (!map_lookup(&tracked, &tid)) return 0;
 map_delete(&write_pending, &tid);
 observe_pipe((int)ctx->args[0], 2);
 if (ignored_io((int)ctx->args[0])) return 0;
 struct write_pending_value value = { .ns = ktime(), .fd = ctx->args[0] };
 value.regular = regular_identity(value.fd, id >> 32, &value.identity);
 if (value.regular) {
  if (map_lookup(&write_seen, &value.identity)) return 0;
  __u64 *last = map_lookup(&write_retry, &value.identity);
  if (last && value.ns >= *last && value.ns - *last < 100000000ULL) return 0;
 }
 if (map_update(&write_pending, &tid, &value, BPF_ANY)) count_loss(5);
 return 0;
}
static __always_inline int handle_write_exit(struct syscall_exit *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id; if (!map_lookup(&tracked, &tid)) return 0;
 struct write_pending_value *pending = map_lookup(&write_pending, &tid);
 if (!pending) return 0;
 if (ctx->ret > 0) {
  struct fd_event *e = reserve(&events, sizeof(*e), 0);
  if (!e) count_loss(1);
  else {
   __builtin_memset(e, 0, sizeof(*e)); e->ns = pending->ns; e->pid = id >> 32; e->tid = tid; e->dirfd = pending->fd; e->kind = 18;
   if (pending->regular) { e->identity = pending->identity; __u64 now = ktime(); map_update(&write_retry, &pending->identity, &now, BPF_ANY); }
   submit(e, 0);
  }
 }
 map_delete(&write_pending, &tid); return 0;
}
SEC("tracepoint/syscalls/sys_enter_write") int write_event(struct syscall_enter *ctx) { return handle_write(ctx); }
SEC("tracepoint/syscalls/sys_exit_write") int write_exit(struct syscall_exit *ctx) { return handle_write_exit(ctx); }
SEC("tracepoint/syscalls/sys_enter_pwrite64") int pwrite_event(struct syscall_enter *ctx) { return handle_write(ctx); }
SEC("tracepoint/syscalls/sys_exit_pwrite64") int pwrite_exit(struct syscall_exit *ctx) { return handle_write_exit(ctx); }
SEC("tracepoint/syscalls/sys_enter_writev") int writev_event(struct syscall_enter *ctx) { return handle_write(ctx); }
SEC("tracepoint/syscalls/sys_exit_writev") int writev_exit(struct syscall_exit *ctx) { return handle_write_exit(ctx); }
SEC("tracepoint/syscalls/sys_enter_pwritev") int pwritev_event(struct syscall_enter *ctx) { return handle_write(ctx); }
SEC("tracepoint/syscalls/sys_exit_pwritev") int pwritev_exit(struct syscall_exit *ctx) { return handle_write_exit(ctx); }
SEC("tracepoint/syscalls/sys_enter_pwritev2") int pwritev2_event(struct syscall_enter *ctx) { return handle_write(ctx); }
SEC("tracepoint/syscalls/sys_exit_pwritev2") int pwritev2_exit(struct syscall_exit *ctx) { return handle_write_exit(ctx); }
// Connect records the supplied sockaddr, not the eventual connection outcome.
SEC("tracepoint/syscalls/sys_enter_connect") int connect_event(struct syscall_enter *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id; if (!map_lookup(&tracked, &tid)) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0); if (!e) { count_loss(1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = ctx->args[0]; e->kind = 19;
 __u32 len = ctx->args[2]; if (len > 128) len = 128;
 e->path_result = len < 2 ? -22 : read_user(e->path, len, (void *)ctx->args[1]);
 if (e->path_result == 0) e->path_result = len;
 unsigned short type = socket_type(ctx->args[0]); e->path[128] = type & 255; e->path[129] = type >> 8;
 map_delete(&tcp_entered, &tid);
 __u16 family = (__u8)e->path[0] | ((__u16)(__u8)e->path[1] << 8);
 if (type == 1 && (family == 2 || family == 10)) {
  __u64 sk = socket_sock((int)ctx->args[0]);
  if (sk) { struct tcp_track track = { .token = e->ns, .pid = id >> 32, .tid = tid }; struct tcp_tid entry = { .sk = sk, .token = e->ns };
   if (map_update(&tcp_entered, &tid, &entry, BPF_ANY)) count_loss(6);
   else if (map_update(&tcp_connects, &sk, &track, BPF_ANY)) { map_delete(&tcp_entered, &tid); count_loss(6); }
   else __builtin_memcpy(&e->path[136], &track.token, sizeof(track.token));
  }
 }
 submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_exit_connect") int connect_exit(struct syscall_exit *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id; if (!map_lookup(&tracked, &tid)) return 0;
 struct fd_event *e = reserve(&events, sizeof(*e), 0); if (!e) { count_loss(1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = tid; e->dirfd = ctx->ret; e->kind = 19;
 struct tcp_tid *entry = map_lookup(&tcp_entered, &tid);
 if (entry && ctx->ret != -115 && ctx->ret != -114) { struct tcp_track *track = map_lookup(&tcp_connects, &entry->sk); if (track && track->token == entry->token) map_delete(&tcp_connects, &entry->sk); }
 map_delete(&tcp_entered, &tid); submit(e, 0); return 0;
}
SEC("tracepoint/sock/inet_sock_set_state") int tcp_state(struct tcp_state_ctx *ctx) {
 if (ctx->protocol != 6 || ctx->oldstate != 2 || (ctx->newstate != 1 && ctx->newstate != 7)) return 0;
 __u64 sk = ctx->sk; struct tcp_track *track = map_lookup(&tcp_connects, &sk); if (!track) return 0;
 struct fd_event *e = reserve(&events, sizeof(*e), 0);
 if (!e) count_loss(1);
 else { __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = track->pid; e->tid = track->tid; e->kind = 22; e->dirfd = ctx->newstate; e->identity.process_start = track->token; submit(e, 0); }
 map_delete(&tcp_connects, &sk); return 0;
}
SEC("tracepoint/syscalls/sys_enter_mmap") int mmap_event(struct syscall_enter *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 // Anonymous mappings do not refer to a file descriptor.
 if (ctx->args[3] & 0x20) return 0;
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { count_loss(1); return 0; }
 __u32 one = 1; if (map_update(&mmap_pending, &tid, &one, BPF_ANY)) { count_loss(4); }
 __builtin_memset(e, 0, sizeof(*e)); e->ns = ktime(); e->pid = id >> 32; e->tid = tid; e->dirfd = ctx->args[4]; e->kind = 6; submit(e, 0); return 0;
}
SEC("tracepoint/syscalls/sys_exit_mmap") int mmap_exit(struct syscall_exit *ctx) {
 __u64 id = pid_tgid(); __u32 tid = id, zero = 0; if (!map_lookup(&tracked, &tid)) return 0;
 if (!map_lookup(&mmap_pending, &tid)) return 0;
 map_delete(&mmap_pending, &tid);
 struct event *e = reserve(&events, sizeof(*e), 0);
 if (!e) { count_loss(1); return 0; }
 __builtin_memset(e, 0, sizeof(*e)); e->tid = tid; e->ns = ctx->ret; e->kind = 6; submit(e, 0); return 0;
}
char LICENSE[] SEC("license") = "GPL";

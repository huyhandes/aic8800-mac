/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * lkpi: the small slice of the Linux kernel API that the vendored rtw89
 * driver needs, implemented in macOS userspace (pthreads + libusb).
 * Written from scratch; Linux headers were only consulted for constant values.
 */
#ifndef LKPI_H
#define LKPI_H

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ---------- types ---------- */
typedef uint8_t u8;   typedef int8_t s8;
typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32;
typedef uint64_t u64; typedef int64_t s64;
typedef u8 __u8; typedef u16 __u16; typedef u32 __u32; typedef u64 __u64;
typedef s8 __s8; typedef s16 __s16; typedef s32 __s32; typedef s64 __s64;
typedef u16 __le16; typedef u32 __le32; typedef u64 __le64;
typedef u16 __be16; typedef u32 __be32; typedef u64 __be64;
typedef u16 __sum16;
typedef unsigned int gfp_t;
typedef u64 dma_addr_t;
typedef s64 ktime_t;
typedef unsigned long kernel_ulong_t;
typedef unsigned short umode_t;
typedef long long loff_t_;
#define loff_t loff_t_

#define GFP_KERNEL 0u
#define GFP_ATOMIC 1u
#define GFP_NOWAIT 2u
#define __GFP_ZERO 0x100u

/* ---------- compiler ---------- */
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#undef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#define noinline __attribute__((__noinline__))
#define __must_check __attribute__((__warn_unused_result__))
#define __maybe_unused __attribute__((__unused__))
#define __always_unused __attribute__((__unused__))
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#define __acquires(x)
#define __releases(x)
#define __must_hold(x)
#define __rcu
#define __iomem
#define __user
#define __force
#define __bitwise
#define __init
#define __exit
#undef __counted_by
#define __counted_by(x)
#define __counted_by_le(x)
#define __nonstring
#undef __cold
#define __cold
#define fallthrough __attribute__((__fallthrough__))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define barrier() __asm__ __volatile__("" ::: "memory")
#define smp_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define smp_rmb() smp_mb()
#define smp_wmb() smp_mb()
#define mb() smp_mb()
#define wmb() smp_mb()
#define rmb() smp_mb()
#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)
#define __same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
#define typecheck(type, x) ({ type __d; __typeof__(x) __x; (void)(&__d == &__x); 1; })
/* like the kernel, only conditions the compiler can fold are checked */
#define BUILD_BUG_ON(c) \
	do { _Static_assert(__builtin_choose_expr(__builtin_constant_p(c), !(c), 1), "BUILD_BUG_ON: " #c); } while (0)
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int : (-!!(e)); })))
#define __static_assert_1(e, msg, ...) _Static_assert(e, msg)
#define static_assert(...) __static_assert_1(__VA_ARGS__, #__VA_ARGS__)
#define IS_ENABLED(x) 0
#define KBUILD_MODNAME "rtw89"
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)
#define MODULE_FIRMWARE(x)
#define MODULE_PARM_DESC(a, b)
#define MODULE_DEVICE_TABLE(t, n)
#define module_param_named(name, var, type, perm)

/* ---------- arithmetic helpers ---------- */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define container_of_const(ptr, type, member) container_of(ptr, type, member)
#define sizeof_field(t, m) sizeof(((t *)0)->m)
#define offsetofend(t, m) (offsetof(t, m) + sizeof_field(t, m))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (size_t)(n))
#define struct_size_t(type, member, n) (sizeof(type) + sizeof(((type *)0)->member[0]) * (size_t)(n))
#define flex_array_size(p, member, n) (sizeof((p)->member[0]) * (size_t)(n))
#define DECLARE_FLEX_ARRAY(type, name) struct { struct { } __empty_##name; type name[]; }
#define min(a, b) ({ __auto_type _a = (a); __auto_type _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ __auto_type _a = (a); __auto_type _b = (b); _a > _b ? _a : _b; })
#define min3(a, b, c) min(min(a, b), c)
#define max3(a, b, c) max(max(a, b), c)
#define min_t(t, a, b) ({ t _a = (a); t _b = (b); _a < _b ? _a : _b; })
#define max_t(t, a, b) ({ t _a = (a); t _b = (b); _a > _b ? _a : _b; })
#define umin(a, b) min_t(unsigned long long, a, b)
#define umax(a, b) max_t(unsigned long long, a, b)
#define clamp(v, lo, hi) min(max(v, lo), hi)
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
#define clamp_val(v, lo, hi) clamp_t(__typeof__(v), v, lo, hi)
#undef abs
#define abs(x) ({ __auto_type _x = (x); _x < 0 ? -_x : _x; })
#define swap(a, b) do { __auto_type _t = (a); (a) = (b); (b) = _t; } while (0)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_DOWN_ULL(n, d) ((unsigned long long)(n) / (d))
#define DIV_ROUND_CLOSEST(x, d) ({ __auto_type _x = (x); __auto_type _d = (d); \
	((_x) > 0) == ((_d) > 0) ? ((_x) + (_d) / 2) / (_d) : ((_x) - (_d) / 2) / (_d); })
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define rounddown(x, y) ((x) - ((x) % (y)))
#define round_up(x, y) ((((x) - 1) | ((__typeof__(x))((y) - 1))) + 1)
#define round_down(x, y) ((x) & ~((__typeof__(x))((y) - 1)))
#define ALIGN(x, a) (((x) + ((__typeof__(x))(a) - 1)) & ~((__typeof__(x))(a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((__typeof__(x))(a) - 1))
#define IS_ALIGNED(x, a) (((x) & ((__typeof__(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a) ((__typeof__(p))ALIGN((uintptr_t)(p), (a)))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define upper_32_bits(n) ((u32)(((u64)(n)) >> 32))
#define U8_MAX 0xff
#define S8_MAX 127
#define S8_MIN (-128)
#define U16_MAX 0xffff
#define S16_MAX 32767
#define S16_MIN (-32768)
#define U32_MAX 0xffffffffu
#define S32_MAX INT32_MAX
#define S32_MIN INT32_MIN
#define U64_MAX UINT64_MAX
#define BITS_PER_BYTE 8
#define BITS_PER_LONG 64
#define BITS_PER_TYPE(t) (sizeof(t) * BITS_PER_BYTE)
#define BITS_TO_BYTES(n) DIV_ROUND_UP(n, BITS_PER_BYTE)
#define BITS_TO_LONGS(n) DIV_ROUND_UP(n, BITS_PER_LONG)
#define PAGE_SIZE 4096
#define SZ_1K 0x400
#define SZ_2K 0x800
#define SZ_4K 0x1000
#define SZ_8K 0x2000
#define SZ_16K 0x4000
#define SZ_32K 0x8000
#define SZ_64K 0x10000
#define SZ_1M 0x100000
#define NSEC_PER_USEC 1000L
#define NSEC_PER_MSEC 1000000L
#define USEC_PER_MSEC 1000L
#define MSEC_PER_SEC 1000L
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L

static inline u64 div_u64(u64 a, u32 b) { return a / b; }
static inline s64 div_s64(s64 a, s32 b) { return a / b; }
static inline u64 div_u64_rem(u64 a, u32 b, u32 *rem) { *rem = a % b; return a / b; }
static inline u64 div64_u64(u64 a, u64 b) { return a / b; }
static inline u64 roundup_u64(u64 x, u32 y) { return DIV_ROUND_UP(x, y) * y; }
#define do_div(n, base) ({ u32 _r = (n) % (base); (n) /= (base); _r; })
static inline s32 sign_extend32(u32 v, int index)
{ u8 s = 31 - index; return (s32)(v << s) >> s; }
static inline s64 sign_extend64(u64 v, int index)
{ u8 s = 63 - index; return (s64)(v << s) >> s; }

/* ---------- bits / bitfield ---------- */
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_MAX(m) ((__typeof__(m))((m) >> __bf_shf(m)))
#define FIELD_FIT(m, v) (!((((__typeof__(m))(v)) << __bf_shf(m)) & ~(m)))
#define FIELD_PREP(m, v) ((((__typeof__(m))(v)) << __bf_shf(m)) & (m))
#define FIELD_PREP_CONST(m, v) FIELD_PREP(m, v)
#define FIELD_GET(m, r) ((__typeof__(m))(((r) & (m)) >> __bf_shf(m)))
#define FIELD_GET_SIGNED(m, r) ({ __auto_type _m = (m); \
	(long long)sign_extend64(FIELD_GET(_m, r), __builtin_popcountll(_m) - 1); })
#define field_multiplier(f) ((f) & -(f))
#define field_mask(f) ((f) / field_multiplier(f))
#define field_get(m, r) (((r) & (m)) / field_multiplier(m))
#define field_prep(m, v) (((v) * field_multiplier(m)) & (m))
#define LKPI_BITS(T, B) \
static inline T B##_encode_bits(T v, T f) { return (T)((v & field_mask(f)) * field_multiplier(f)); } \
static inline T B##_get_bits(T v, T f) { return (T)((v & f) / field_multiplier(f)); } \
static inline T B##_replace_bits(T old, T v, T f) { return (T)((old & ~f) | B##_encode_bits(v, f)); } \
static inline void B##p_replace_bits(T *p, T v, T f) { *p = B##_replace_bits(*p, v, f); }
LKPI_BITS(u8, u8)
LKPI_BITS(u16, u16)
LKPI_BITS(u32, u32)
LKPI_BITS(u64, u64)
/* little-endian host: le* helpers are the plain ones */
#define le16_encode_bits(v, f) u16_encode_bits(v, f)
#define le32_encode_bits(v, f) u32_encode_bits(v, f)
#define le64_encode_bits(v, f) u64_encode_bits(v, f)
#define le16_get_bits(v, f) u16_get_bits(v, f)
#define le32_get_bits(v, f) u32_get_bits(v, f)
#define le64_get_bits(v, f) u64_get_bits(v, f)
#define le16_replace_bits(o, v, f) u16_replace_bits(o, v, f)
#define le32_replace_bits(o, v, f) u32_replace_bits(o, v, f)
#define le16p_replace_bits(p, v, f) u16p_replace_bits(p, v, f)
#define le32p_replace_bits(p, v, f) u32p_replace_bits(p, v, f)
#define le64p_replace_bits(p, v, f) u64p_replace_bits(p, v, f)

static inline unsigned int hweight8(unsigned int w) { return __builtin_popcount(w & 0xff); }
static inline unsigned int hweight16(unsigned int w) { return __builtin_popcount(w & 0xffff); }
#define hweight32(w) ((unsigned int)__builtin_popcount((u32)(w))) /* usable in static_assert */
static inline unsigned int hweight64(u64 w) { return __builtin_popcountll(w); }
static inline unsigned long hweight_long(unsigned long w) { return __builtin_popcountl(w); }
static inline unsigned long __ffs(unsigned long w) { return __builtin_ctzl(w); }
static inline unsigned long __fls(unsigned long w) { return 63 - __builtin_clzl(w); }
#define fls lkpi_fls /* darwin <strings.h> has fls/ffs */
#define ffs lkpi_ffs
static inline int fls(unsigned int x) { return x ? 32 - __builtin_clz(x) : 0; }
static inline int fls64(u64 x) { return x ? 64 - __builtin_clzll(x) : 0; }
static inline int ffs(int x) { return __builtin_ffs(x); }
#define ilog2(n) ((int)(63 - __builtin_clzll((u64)(n))))
#define is_power_of_2(n) ((n) != 0 && (((n) & ((n) - 1)) == 0))
static inline unsigned long roundup_pow_of_two(unsigned long n) { return 1UL << fls64(n - 1); }

/* atomic bitops on unsigned long arrays */
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]
static inline void set_bit(long nr, volatile unsigned long *a)
{ __atomic_fetch_or(&a[BIT_WORD(nr)], BIT_MASK(nr), __ATOMIC_SEQ_CST); }
static inline void clear_bit(long nr, volatile unsigned long *a)
{ __atomic_fetch_and(&a[BIT_WORD(nr)], ~BIT_MASK(nr), __ATOMIC_SEQ_CST); }
static inline bool test_bit(long nr, const volatile unsigned long *a)
{ return (__atomic_load_n(&a[BIT_WORD(nr)], __ATOMIC_RELAXED) & BIT_MASK(nr)) != 0; }
static inline bool test_and_set_bit(long nr, volatile unsigned long *a)
{ return (__atomic_fetch_or(&a[BIT_WORD(nr)], BIT_MASK(nr), __ATOMIC_SEQ_CST) & BIT_MASK(nr)) != 0; }
static inline bool test_and_clear_bit(long nr, volatile unsigned long *a)
{ return (__atomic_fetch_and(&a[BIT_WORD(nr)], ~BIT_MASK(nr), __ATOMIC_SEQ_CST) & BIT_MASK(nr)) != 0; }
#define __set_bit set_bit
#define __clear_bit clear_bit
#define __test_and_set_bit test_and_set_bit
#define __test_and_clear_bit test_and_clear_bit
static inline void assign_bit(long nr, volatile unsigned long *a, bool v)
{ if (v) set_bit(nr, a); else clear_bit(nr, a); }
#define __assign_bit assign_bit
unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long off);
unsigned long find_next_zero_bit(const unsigned long *a, unsigned long size, unsigned long off);
#define find_first_bit(a, size) find_next_bit(a, size, 0)
#define find_first_zero_bit(a, size) find_next_zero_bit(a, size, 0)
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), 0); (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), 0); (bit) < (size); \
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
static inline void bitmap_zero(unsigned long *d, unsigned int n)
{ memset(d, 0, BITS_TO_LONGS(n) * sizeof(long)); }
void bitmap_fill(unsigned long *d, unsigned int n);
static inline void bitmap_copy(unsigned long *d, const unsigned long *s, unsigned int n)
{ memcpy(d, s, BITS_TO_LONGS(n) * sizeof(long)); }
static inline void bitmap_or(unsigned long *d, const unsigned long *a, const unsigned long *b, unsigned int n)
{ for (unsigned int i = 0; i < BITS_TO_LONGS(n); i++) d[i] = a[i] | b[i]; }
static inline bool bitmap_and(unsigned long *d, const unsigned long *a, const unsigned long *b, unsigned int n)
{ unsigned long r = 0; for (unsigned int i = 0; i < BITS_TO_LONGS(n); i++) r |= (d[i] = a[i] & b[i]); return r != 0; }
static inline bool bitmap_empty(const unsigned long *s, unsigned int n) { return find_next_bit(s, n, 0) >= n; }
static inline bool bitmap_full(const unsigned long *s, unsigned int n) { return find_next_zero_bit(s, n, 0) >= n; }
unsigned int bitmap_weight(const unsigned long *s, unsigned int n);
static inline bool bitmap_equal(const unsigned long *a, const unsigned long *b, unsigned int n)
{ for (unsigned int i = 0; i < n; i++) if (test_bit(i, a) != test_bit(i, b)) return false; return true; }

/* ---------- byte order (host is little-endian arm64) ---------- */
#define cpu_to_le16(x) ((__le16)(x))
#define cpu_to_le32(x) ((__le32)(x))
#define cpu_to_le64(x) ((__le64)(x))
#define le16_to_cpu(x) ((u16)(x))
#define le32_to_cpu(x) ((u32)(x))
#define le64_to_cpu(x) ((u64)(x))
#define cpu_to_be16(x) ((__be16)__builtin_bswap16(x))
#define cpu_to_be32(x) ((__be32)__builtin_bswap32(x))
#define cpu_to_be64(x) ((__be64)__builtin_bswap64(x))
#define be16_to_cpu(x) ((u16)__builtin_bswap16(x))
#define be32_to_cpu(x) ((u32)__builtin_bswap32(x))
#define be64_to_cpu(x) ((u64)__builtin_bswap64(x))
#define le16_to_cpup(p) (*(const u16 *)(p))
#define le32_to_cpup(p) (*(const u32 *)(p))
#define le16_add_cpu(p, v) (*(p) += (v))
#define le32_add_cpu(p, v) (*(p) += (v))
#undef htons
#undef ntohs
#undef htonl
#undef ntohl
#define htons(x) cpu_to_be16(x)
#define ntohs(x) be16_to_cpu(x)
#define htonl(x) cpu_to_be32(x)
#define ntohl(x) be32_to_cpu(x)
#define swab16(x) __builtin_bswap16(x)
#define swab32(x) __builtin_bswap32(x)
static inline u16 get_unaligned_le16(const void *p) { u16 v; memcpy(&v, p, 2); return v; }
static inline u32 get_unaligned_le32(const void *p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 get_unaligned_le64(const void *p) { u64 v; memcpy(&v, p, 8); return v; }
static inline u16 get_unaligned_be16(const void *p) { u16 v; memcpy(&v, p, 2); return be16_to_cpu(v); }
static inline u32 get_unaligned_be32(const void *p) { u32 v; memcpy(&v, p, 4); return be32_to_cpu(v); }
static inline void put_unaligned_le16(u16 v, void *p) { memcpy(p, &v, 2); }
static inline void put_unaligned_le32(u32 v, void *p) { memcpy(p, &v, 4); }
static inline void put_unaligned_le64(u64 v, void *p) { memcpy(p, &v, 8); }
#define get_unaligned(p) ({ __typeof__(*(p)) _v; memcpy(&_v, (p), sizeof(_v)); _v; })
#define put_unaligned(v, p) ({ __typeof__(*(p)) _v = (v); memcpy((p), &_v, sizeof(_v)); })

/* ---------- errors ---------- */
#define MAX_ERRNO 4095
#define ENOTSUPP 524
#define EPROBE_DEFER 517
#ifndef ENOTSUP
#define ENOTSUP EOPNOTSUPP
#endif
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long e) { return (void *)e; }
static inline long PTR_ERR(const void *p) { return (long)p; }
static inline bool IS_ERR(const void *p) { return IS_ERR_VALUE((unsigned long)p); }
static inline bool IS_ERR_OR_NULL(const void *p) { return !p || IS_ERR(p); }
#define ERR_CAST(p) ((void *)(p))
#define PTR_ERR_OR_ZERO(p) (IS_ERR(p) ? PTR_ERR(p) : 0)

/* ---------- memory ---------- */
void *lkpi_kmalloc(size_t n, gfp_t gfp);
static inline void *kmalloc(size_t n, gfp_t gfp) { return lkpi_kmalloc(n, gfp); }
static inline void *kzalloc(size_t n, gfp_t gfp) { return calloc(1, n ? n : 1); }
static inline void *kcalloc(size_t n, size_t s, gfp_t gfp) { return calloc(n ? n : 1, s ? s : 1); }
static inline void *kmalloc_array(size_t n, size_t s, gfp_t gfp) { return kcalloc(n, s, gfp); }
static inline void *krealloc(void *p, size_t n, gfp_t gfp) { return realloc(p, n); }
static inline void kfree(const void *p) { free((void *)p); }
static inline void kvfree(const void *p) { free((void *)p); }
static inline void kfree_sensitive(const void *p) { free((void *)p); }
static inline void *kmemdup(const void *s, size_t n, gfp_t gfp)
{ void *p = malloc(n ? n : 1); if (p) memcpy(p, s, n); return p; }
static inline void *vmalloc(size_t n) { return malloc(n ? n : 1); }
static inline void *vzalloc(size_t n) { return calloc(1, n ? n : 1); }
static inline void vfree(const void *p) { free((void *)p); }
#define kvzalloc(n, g) vzalloc(n)
#define kvmalloc(n, g) vmalloc(n)
#define __lkpi_gfp(...) (GFP_KERNEL __VA_OPT__(| (__VA_ARGS__)))
#define kmalloc_obj(VAR, ...) kmalloc(sizeof(VAR), __lkpi_gfp(__VA_ARGS__))
#define kzalloc_obj(VAR, ...) kzalloc(sizeof(VAR), __lkpi_gfp(__VA_ARGS__))
#define kmalloc_objs(VAR, N, ...) kmalloc_array(N, sizeof(VAR), __lkpi_gfp(__VA_ARGS__))
#define kzalloc_objs(VAR, N, ...) kcalloc(N, sizeof(VAR), __lkpi_gfp(__VA_ARGS__))
#define kzalloc_flex(VAR, FAM, N, ...) kzalloc(struct_size_t(__typeof__(VAR), FAM, N), __lkpi_gfp(__VA_ARGS__))
#define kmalloc_flex(VAR, FAM, N, ...) kmalloc(struct_size_t(__typeof__(VAR), FAM, N), __lkpi_gfp(__VA_ARGS__))
/* shortcut: devm_* allocations live until process exit (the daemon exits on unplug), add devres tracking if hot-replug in-process is needed */
#define devm_kzalloc(dev, n, gfp) kzalloc(n, gfp)
#define devm_kmalloc(dev, n, gfp) kmalloc(n, gfp)
#define devm_kcalloc(dev, n, s, gfp) kcalloc(n, s, gfp)
#define devm_kmemdup(dev, s, n, gfp) kmemdup(s, n, gfp)
#define devm_kfree(dev, p) kfree(p)
#define devm_kzalloc_obj(dev, VAR, ...) kzalloc_obj(VAR, ##__VA_ARGS__)
#define devm_kzalloc_objs(dev, VAR, N, ...) kzalloc_objs(VAR, N, ##__VA_ARGS__)
#define devm_kzalloc_flex(dev, VAR, FAM, N, ...) kzalloc_flex(VAR, FAM, N, ##__VA_ARGS__)
/* the cleanup.h __free(kfree) attribute */
static inline void __lkpi_free_kfree(void *p) { free(*(void **)p); }
#define __free(name) __attribute__((__cleanup__(__lkpi_free_##name)))
#define no_free_ptr(p) ({ __auto_type _p = (p); (p) = NULL; _p; })
#define return_ptr(p) return no_free_ptr(p)

/* ---------- strings / formatting ---------- */
struct va_format { const char *fmt; va_list *va; };
int lkpi_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
int lkpi_snprintf(char *buf, size_t size, const char *fmt, ...) __printf(3, 4);
int scnprintf(char *buf, size_t size, const char *fmt, ...) __printf(3, 4);
int sysfs_emit(char *buf, const char *fmt, ...) __printf(2, 3);
#undef snprintf
#undef vsnprintf
#undef sprintf
#define snprintf lkpi_snprintf
#define vsnprintf lkpi_vsnprintf
#define sprintf(buf, ...) lkpi_snprintf(buf, 4096, __VA_ARGS__)
static inline ssize_t lkpi_strscpy(char *d, const char *s, size_t n)
{ size_t l = strlcpy(d, s, n); return l >= n ? -E2BIG : (ssize_t)l; }
#define __lkpi_strscpy2(d, s) lkpi_strscpy(d, s, sizeof(d))
#define __lkpi_strscpy3(d, s, n) lkpi_strscpy(d, s, n)
#define __lkpi_pick3(_1, _2, _3, N, ...) N
#define strscpy(...) __lkpi_pick3(__VA_ARGS__, __lkpi_strscpy3, __lkpi_strscpy2, 0)(__VA_ARGS__)
void *memchr_inv(const void *s, int c, size_t n);
int hex2bin(u8 *dst, const char *src, size_t count);
int kstrtobool(const char *s, bool *res);
int kstrtoint(const char *s, unsigned int base, int *res);
int kstrtouint(const char *s, unsigned int base, unsigned int *res);
int kstrtou32(const char *s, unsigned int base, u32 *res);
int kstrtou16(const char *s, unsigned int base, u16 *res);
int kstrtou8(const char *s, unsigned int base, u8 *res);
int kstrtoul(const char *s, unsigned int base, unsigned long *res);
int kstrtos8(const char *s, unsigned int base, s8 *res);
static inline const char *str_on_off(bool v) { return v ? "on" : "off"; }
static inline const char *str_yes_no(bool v) { return v ? "yes" : "no"; }
static inline const char *str_enable_disable(bool v) { return v ? "enable" : "disable"; }
static inline const char *str_disable_enable(bool v) { return v ? "disable" : "enable"; }
static inline const char *str_enabled_disabled(bool v) { return v ? "enabled" : "disabled"; }
static inline const char *str_read_write(bool v) { return v ? "read" : "write"; }
static inline const char *str_true_false(bool v) { return v ? "true" : "false"; }
#define hex_asc_upper "0123456789ABCDEF"
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *),
	  void (*swap_fn)(void *, void *, int));
ssize_t simple_read_from_buffer(void *to, size_t count, loff_t *ppos, const void *from, size_t available);
static inline unsigned long copy_from_user(void *to, const void *from, unsigned long n)
{ memcpy(to, from, n); return 0; }

/* ---------- logging ---------- */
extern unsigned int lkpi_loglevel;
void lkpi_log(int level, const char *fmt, ...) __printf(2, 3);
#define KERN_ERR "<3>"
#define KERN_WARNING "<4>"
#define KERN_INFO "<6>"
#define KERN_DEBUG "<7>"
#define printk(...) lkpi_log(6, __VA_ARGS__)
#define pr_err(...) lkpi_log(3, __VA_ARGS__)
#define pr_warn(...) lkpi_log(4, __VA_ARGS__)
#define pr_info(...) lkpi_log(6, __VA_ARGS__)
#define pr_debug(...) lkpi_log(7, __VA_ARGS__)
#define pr_err_once pr_err
#define pr_warn_once pr_warn
struct device;
#define dev_err(d, ...) lkpi_log(3, __VA_ARGS__)
#define dev_warn(d, ...) lkpi_log(4, __VA_ARGS__)
#define dev_info(d, ...) lkpi_log(6, __VA_ARGS__)
#define dev_dbg(d, ...) lkpi_log(7, __VA_ARGS__)
#define dev_notice(d, ...) lkpi_log(5, __VA_ARGS__)
#define dev_err_ratelimited dev_err
#define dev_warn_ratelimited dev_warn
#define dev_info_ratelimited dev_info
#define dev_printk(lvl, d, ...) lkpi_log((lvl)[1] - '0', __VA_ARGS__)
#define __lkpi_once(stmt) ({ static bool _done; if (!_done) { _done = true; stmt; } })
#define dev_info_once(d, ...) __lkpi_once(dev_info(d, __VA_ARGS__))
#define dev_warn_once(d, ...) __lkpi_once(dev_warn(d, __VA_ARGS__))
#define dev_err_once(d, ...) __lkpi_once(dev_err(d, __VA_ARGS__))
#define WARN(c, ...) ({ int _c = !!(c); if (unlikely(_c)) lkpi_log(4, "WARNING %s:%d: ", __FILE__, __LINE__), lkpi_log(4, __VA_ARGS__); unlikely(_c); })
#define WARN_ON(c) ({ int _c = !!(c); if (unlikely(_c)) lkpi_log(4, "WARNING %s:%d: %s\n", __FILE__, __LINE__, #c); unlikely(_c); })
#define WARN_ONCE(c, ...) ({ static bool _w; int _c = !!(c); if (unlikely(_c) && !_w) { _w = true; WARN(1, __VA_ARGS__); } unlikely(_c); })
#define WARN_ON_ONCE(c) ({ static bool _w; int _c = !!(c); if (unlikely(_c) && !_w) { _w = true; WARN_ON(1); } unlikely(_c); })
#define BUG() abort()
#define BUG_ON(c) do { if (unlikely(c)) abort(); } while (0)
#define DUMP_PREFIX_NONE 0
#define DUMP_PREFIX_OFFSET 1
#define DUMP_PREFIX_ADDRESS 2
void print_hex_dump(const char *level, const char *prefix, int type, int rowsize,
		    int groupsize, const void *buf, size_t len, bool ascii);
#define print_hex_dump_bytes(prefix, type, buf, len) \
	print_hex_dump(KERN_DEBUG, prefix, type, 16, 1, buf, len, true)
#define print_hex_dump_debug print_hex_dump

/* ---------- lists ---------- */
struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *p, struct list_head *nx)
{ nx->prev = n; n->next = nx; n->prev = p; p->next = n; }
static inline void list_add(struct list_head *n, struct list_head *h) { __list_add(n, h, h->next); }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { __list_add(n, h->prev, h); }
static inline void __list_del(struct list_head *p, struct list_head *n) { n->prev = p; p->next = n; }
static inline void list_del(struct list_head *e) { __list_del(e->prev, e->next); e->next = e->prev = NULL; }
static inline void list_del_init(struct list_head *e) { __list_del(e->prev, e->next); INIT_LIST_HEAD(e); }
static inline bool list_empty(const struct list_head *h) { return READ_ONCE(h->next) == h; }
static inline bool list_is_singular(const struct list_head *h) { return !list_empty(h) && h->next == h->prev; }
static inline void list_move(struct list_head *e, struct list_head *h) { __list_del(e->prev, e->next); list_add(e, h); }
static inline void list_move_tail(struct list_head *e, struct list_head *h) { __list_del(e->prev, e->next); list_add_tail(e, h); }
static inline bool list_is_last(const struct list_head *e, const struct list_head *h) { return e->next == h; }
static inline bool list_is_first(const struct list_head *e, const struct list_head *h) { return e->prev == h; }
static inline void __list_splice(const struct list_head *l, struct list_head *p, struct list_head *n)
{ struct list_head *f = l->next, *t = l->prev; f->prev = p; p->next = f; t->next = n; n->prev = t; }
static inline void list_splice(const struct list_head *l, struct list_head *h) { if (!list_empty(l)) __list_splice(l, h, h->next); }
static inline void list_splice_tail(struct list_head *l, struct list_head *h) { if (!list_empty(l)) __list_splice(l, h->prev, h); }
static inline void list_splice_init(struct list_head *l, struct list_head *h) { if (!list_empty(l)) { __list_splice(l, h, h->next); INIT_LIST_HEAD(l); } }
static inline void list_splice_tail_init(struct list_head *l, struct list_head *h) { if (!list_empty(l)) { __list_splice(l, h->prev, h); INIT_LIST_HEAD(l); } }
static inline size_t list_count_nodes(struct list_head *h) { size_t n = 0; for (struct list_head *p = h->next; p != h; p = p->next) n++; return n; }
#define list_entry(p, t, m) container_of(p, t, m)
#define list_first_entry(h, t, m) list_entry((h)->next, t, m)
#define list_last_entry(h, t, m) list_entry((h)->prev, t, m)
#define list_first_entry_or_null(h, t, m) ({ struct list_head *_h = (h), *_n = READ_ONCE(_h->next); _n != _h ? list_entry(_n, t, m) : NULL; })
#define list_next_entry(p, m) list_entry((p)->m.next, __typeof__(*(p)), m)
#define list_prev_entry(p, m) list_entry((p)->m.prev, __typeof__(*(p)), m)
#define list_entry_is_head(p, h, m) (&(p)->m == (h))
#define list_for_each(p, h) for (p = (h)->next; p != (h); p = p->next)
#define list_for_each_safe(p, n, h) for (p = (h)->next, n = p->next; p != (h); p = n, n = p->next)
#define list_for_each_entry(p, h, m) \
	for (p = list_first_entry(h, __typeof__(*p), m); !list_entry_is_head(p, h, m); p = list_next_entry(p, m))
#define list_for_each_entry_reverse(p, h, m) \
	for (p = list_last_entry(h, __typeof__(*p), m); !list_entry_is_head(p, h, m); p = list_prev_entry(p, m))
#define list_for_each_entry_safe(p, n, h, m) \
	for (p = list_first_entry(h, __typeof__(*p), m), n = list_next_entry(p, m); \
	     !list_entry_is_head(p, h, m); p = n, n = list_next_entry(n, m))
#define list_for_each_entry_continue(p, h, m) \
	for (p = list_next_entry(p, m); !list_entry_is_head(p, h, m); p = list_next_entry(p, m))
#define list_for_each_entry_rcu(p, h, m, ...) list_for_each_entry(p, h, m)
#define list_add_rcu list_add
#define list_add_tail_rcu list_add_tail
#define list_del_rcu list_del

/* ---------- locks ---------- */
typedef struct { pthread_mutex_t m; } spinlock_t;
struct mutex { pthread_mutex_t m; };
void lkpi_lock_init(pthread_mutex_t *m);
#define spin_lock_init(l) lkpi_lock_init(&(l)->m)
#define DEFINE_SPINLOCK(n) spinlock_t n = { PTHREAD_MUTEX_INITIALIZER }
#define DEFINE_MUTEX(n) struct mutex n = { PTHREAD_MUTEX_INITIALIZER }
#define spin_lock(l) pthread_mutex_lock(&(l)->m)
#define spin_unlock(l) pthread_mutex_unlock(&(l)->m)
#define spin_lock_bh spin_lock
#define spin_unlock_bh spin_unlock
#define spin_lock_irq spin_lock
#define spin_unlock_irq spin_unlock
#define spin_lock_irqsave(l, f) do { (f) = 0; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); spin_unlock(l); } while (0)
#define mutex_init(l) lkpi_lock_init(&(l)->m)
#define mutex_destroy(l) pthread_mutex_destroy(&(l)->m)
#define mutex_lock(l) pthread_mutex_lock(&(l)->m)
#define mutex_unlock(l) pthread_mutex_unlock(&(l)->m)
#define mutex_trylock(l) (pthread_mutex_trylock(&(l)->m) == 0)
#define lockdep_assert_held(l) do { } while (0)
#define lockdep_assert_not_held(l) do { } while (0)
#define might_sleep() do { } while (0)
#define local_bh_disable() do { } while (0)
#define local_bh_enable() do { } while (0)
#define local_irq_save(f) ((f) = 0)
#define local_irq_restore(f) ((void)(f))
#define in_interrupt() 0
#define in_atomic() 0

/* RCU: a global count of threads inside a read section; synchronize_rcu waits for it to hit zero */
extern int lkpi_rcu_readers;
extern _Thread_local unsigned int lkpi_rcu_nest;
static inline void rcu_read_lock(void)
{ if (!lkpi_rcu_nest++) __atomic_fetch_add(&lkpi_rcu_readers, 1, __ATOMIC_SEQ_CST); }
static inline void rcu_read_unlock(void)
{ if (!--lkpi_rcu_nest) __atomic_fetch_sub(&lkpi_rcu_readers, 1, __ATOMIC_SEQ_CST); }
#define rcu_dereference(p) READ_ONCE(p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_dereference_check(p, c) READ_ONCE(p)
#define rcu_dereference_raw(p) READ_ONCE(p)
#define rcu_access_pointer(p) READ_ONCE(p)
#define rcu_assign_pointer(p, v) do { __atomic_thread_fence(__ATOMIC_RELEASE); WRITE_ONCE(p, v); } while (0)
#define RCU_INIT_POINTER(p, v) WRITE_ONCE(p, v)
#define lockdep_is_held(l) 1
struct rcu_head { void *unused; };
void synchronize_rcu(void);
void lkpi_defer_free(void *p);
#define kfree_rcu(p, field) lkpi_defer_free(p)
#define synchronize_net synchronize_rcu

/* cleanup.h guards used by rtw89: guard(rcu)() and spinlock variants */
struct __lkpi_guard_rcu { int unused; };
static inline void __lkpi_guard_rcu_exit(struct __lkpi_guard_rcu *g) { (void)g; rcu_read_unlock(); }
#define __lkpi_guard_rcu_init() ({ rcu_read_lock(); (struct __lkpi_guard_rcu){ 0 }; })
typedef spinlock_t *__lkpi_guard_spinlock;
static inline void __lkpi_guard_spinlock_exit(__lkpi_guard_spinlock *g) { if (*g) spin_unlock(*g); }
#define __lkpi_guard_spinlock_init(l) ({ spin_lock(l); (l); })
#define __lkpi_guard_spinlock_bh_exit __lkpi_guard_spinlock_exit
#define __lkpi_guard_spinlock_bh_init __lkpi_guard_spinlock_init
#define __lkpi_guard_spinlock_irqsave_exit __lkpi_guard_spinlock_exit
#define __lkpi_guard_spinlock_irqsave_init __lkpi_guard_spinlock_init
typedef struct mutex *__lkpi_guard_mutex;
static inline void __lkpi_guard_mutex_exit(__lkpi_guard_mutex *g) { if (*g) mutex_unlock(*g); }
#define __lkpi_guard_mutex_init(l) ({ mutex_lock(l); (l); })
#define __lkpi_guard_type_rcu struct __lkpi_guard_rcu
#define __lkpi_guard_type_spinlock __lkpi_guard_spinlock
#define __lkpi_guard_type_spinlock_bh __lkpi_guard_spinlock
#define __lkpi_guard_type_spinlock_irqsave __lkpi_guard_spinlock
#define __lkpi_guard_type_mutex __lkpi_guard_mutex
#define __LKPI_UNIQ(p) __LKPI_CAT(p, __COUNTER__)
#define __LKPI_CAT(a, b) __LKPI_CAT2(a, b)
#define __LKPI_CAT2(a, b) a##b
#define guard(name) __lkpi_guard_type_##name __LKPI_UNIQ(__guard_) \
	__attribute__((__cleanup__(__lkpi_guard_##name##_exit))) = __lkpi_guard_##name##_init
#define scoped_guard(name, ...) \
	for (__lkpi_guard_type_##name __sg __attribute__((__cleanup__(__lkpi_guard_##name##_exit))) = \
	     __lkpi_guard_##name##_init(__VA_ARGS__), *__sgdone = NULL; !__sgdone; __sgdone = (void *)1)

/* ---------- atomics ---------- */
typedef struct { int counter; } atomic_t;
typedef struct { s64 counter; } atomic64_t;
typedef struct { atomic_t refs; } refcount_t;
#define ATOMIC_INIT(i) { (i) }
#define atomic_read(v) __atomic_load_n(&(v)->counter, __ATOMIC_SEQ_CST)
#define atomic_set(v, i) __atomic_store_n(&(v)->counter, (i), __ATOMIC_SEQ_CST)
#define atomic_add_return(i, v) __atomic_add_fetch(&(v)->counter, (i), __ATOMIC_SEQ_CST)
#define atomic_sub_return(i, v) __atomic_sub_fetch(&(v)->counter, (i), __ATOMIC_SEQ_CST)
#define atomic_inc_return(v) atomic_add_return(1, v)
#define atomic_dec_return(v) atomic_sub_return(1, v)
#define atomic_add(i, v) ((void)atomic_add_return(i, v))
#define atomic_sub(i, v) ((void)atomic_sub_return(i, v))
#define atomic_inc(v) atomic_add(1, v)
#define atomic_dec(v) atomic_sub(1, v)
#define atomic_dec_and_test(v) (atomic_dec_return(v) == 0)
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
#define atomic_cmpxchg(v, o, n) ({ __typeof__((v)->counter) _o = (o); \
	__atomic_compare_exchange_n(&(v)->counter, &_o, (n), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); _o; })
#define atomic_xchg(v, n) __atomic_exchange_n(&(v)->counter, (n), __ATOMIC_SEQ_CST)
#define atomic64_read atomic_read
#define atomic64_set atomic_set
#define atomic64_inc_return atomic_inc_return
#define atomic64_inc atomic_inc
#define atomic64_add atomic_add
#define refcount_set(r, n) atomic_set(&(r)->refs, n)
#define refcount_read(r) atomic_read(&(r)->refs)
#define refcount_inc(r) atomic_inc(&(r)->refs)
#define refcount_dec(r) atomic_dec(&(r)->refs)
#define refcount_dec_and_test(r) atomic_dec_and_test(&(r)->refs)
static inline bool refcount_inc_not_zero(refcount_t *r)
{
	int old = atomic_read(&r->refs);
	do {
		if (!old)
			return false;
	} while (!__atomic_compare_exchange_n(&r->refs.counter, &old, old + 1, false,
					      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
	return true;
}

/* ---------- time ---------- */
#define HZ 1000
u64 lkpi_now_ns(void);
u64 lkpi_boot_ns(void);
#define jiffies ((unsigned long)(lkpi_now_ns() / NSEC_PER_MSEC))
#define jiffies_64 ((u64)jiffies)
#define MAX_JIFFY_OFFSET ((LONG_MAX >> 1) - 1)
static inline unsigned long msecs_to_jiffies(unsigned int m) { return m; }
static inline unsigned long usecs_to_jiffies(unsigned int u) { return DIV_ROUND_UP(u, 1000); }
static inline unsigned int jiffies_to_msecs(unsigned long j) { return j; }
static inline unsigned int jiffies_to_usecs(unsigned long j) { return j * 1000; }
static inline unsigned long round_jiffies_relative(unsigned long j) { return j; }
static inline unsigned long round_jiffies_up(unsigned long j) { return j; }
#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b) time_after_eq(b, a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_in_range(a, b, c) (time_after_eq(a, b) && time_before_eq(a, c))
static inline ktime_t ktime_get(void) { return (ktime_t)lkpi_now_ns(); }
static inline ktime_t ktime_get_boottime(void) { return (ktime_t)lkpi_boot_ns(); }
static inline u64 ktime_get_boottime_ns(void) { return lkpi_boot_ns(); }
static inline u64 ktime_get_ns(void) { return lkpi_now_ns(); }
static inline u64 ktime_get_real_ns(void) { return lkpi_now_ns(); }
static inline s64 ktime_to_us(ktime_t t) { return t / NSEC_PER_USEC; }
static inline s64 ktime_to_ms(ktime_t t) { return t / NSEC_PER_MSEC; }
static inline s64 ktime_to_ns(ktime_t t) { return t; }
static inline s64 ktime_us_delta(ktime_t a, ktime_t b) { return ktime_to_us(a - b); }
static inline s64 ktime_ms_delta(ktime_t a, ktime_t b) { return ktime_to_ms(a - b); }
static inline ktime_t ktime_add_us(ktime_t t, u64 us) { return t + us * NSEC_PER_USEC; }
static inline ktime_t ktime_add_ms(ktime_t t, u64 ms) { return t + ms * NSEC_PER_MSEC; }
#define ktime_sub(a, b) ((a) - (b))
#define ktime_add(a, b) ((a) + (b))
#define ktime_compare(a, b) ((a) < (b) ? -1 : (a) > (b))
#define ktime_after(a, b) ((a) > (b))
#define ktime_before(a, b) ((a) < (b))
#define ns_to_ktime(n) ((ktime_t)(n))
void lkpi_sleep_us(u64 us);
void lkpi_delay_us(u64 us);
#define udelay(us) lkpi_delay_us(us)
#define ndelay(ns) lkpi_delay_us(DIV_ROUND_UP(ns, 1000))
#define mdelay(ms) lkpi_delay_us((u64)(ms) * 1000)
#define msleep(ms) lkpi_sleep_us((u64)(ms) * 1000)
#define usleep_range(a, b) lkpi_sleep_us(a)
#define fsleep(us) lkpi_sleep_us(us)
#define ssleep(s) lkpi_sleep_us((u64)(s) * 1000000)
#define cond_resched() do { } while (0)
#define cpu_relax() do { } while (0)

/* linux/iopoll.h */
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, sleep_before_read, args...) ({ \
	u64 __timeout_ns = lkpi_now_ns() + (u64)(timeout_us) * 1000; \
	if ((sleep_before_read) && (sleep_us)) lkpi_sleep_us(sleep_us); \
	for (;;) { \
		bool __expired = (timeout_us) && lkpi_now_ns() > __timeout_ns; \
		(val) = op(args); \
		if (cond) break; \
		if (__expired) break; \
		if (sleep_us) lkpi_sleep_us(sleep_us); \
	} \
	(cond) ? 0 : -ETIMEDOUT; })
/* as upstream: the budget counts only the delays, not the time spent in op (a USB
 * register read is ~100 us), so drivers tuned on Linux poll as often as they expect */
#define poll_timeout_us_atomic(op, cond, delay_us, timeout_us, delay_before_op) ({ \
	u64 __timeout_us = (timeout_us); \
	s64 __left_ns = __timeout_us * NSEC_PER_USEC; \
	unsigned long __delay_us = (delay_us); \
	int ___ret; \
	if ((delay_before_op) && __delay_us) { \
		udelay(__delay_us); \
		__left_ns -= __delay_us * NSEC_PER_USEC; \
	} \
	for (;;) { \
		bool __expired = __timeout_us && __left_ns < 0; \
		barrier(); \
		op; \
		if (cond) { ___ret = 0; break; } \
		if (__expired) { ___ret = -ETIMEDOUT; break; } \
		if (__delay_us) { \
			udelay(__delay_us); \
			__left_ns -= __delay_us * NSEC_PER_USEC; \
		} \
		__left_ns--; \
	} \
	___ret; })
#define read_poll_timeout_atomic(op, val, cond, delay_us, timeout_us, delay_before_read, args...) \
	poll_timeout_us_atomic((val) = op(args), cond, delay_us, timeout_us, delay_before_read)
#define readx_poll_timeout(op, addr, val, cond, sleep_us, timeout_us) \
	read_poll_timeout(op, val, cond, sleep_us, timeout_us, false, addr)
#define poll_timeout_us(op, cond, sleep_us, timeout_us, sleep_before_op) ({ \
	u64 __timeout_ns = lkpi_now_ns() + (u64)(timeout_us) * 1000; \
	if ((sleep_before_op) && (sleep_us)) lkpi_sleep_us(sleep_us); \
	for (;;) { \
		bool __expired = (timeout_us) && lkpi_now_ns() > __timeout_ns; \
		op; \
		if (cond) break; \
		if (__expired) break; \
		if (sleep_us) lkpi_sleep_us(sleep_us); \
	} \
	(cond) ? 0 : -ETIMEDOUT; })

/* ---------- completion ---------- */
struct completion { pthread_mutex_t m; pthread_cond_t c; unsigned int done; };
void init_completion(struct completion *x);
void reinit_completion(struct completion *x);
void complete(struct completion *x);
void complete_all(struct completion *x);
bool completion_done(struct completion *x);
void wait_for_completion(struct completion *x);
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout);
#define DECLARE_COMPLETION_ONSTACK(n) struct completion n; init_completion(&n)

/* ---------- timers / workqueues ---------- */
struct lkpi_timer {
	struct list_head entry;
	u64 expires_ns;
	bool pending;
	void (*fn)(struct lkpi_timer *t);
};
struct workqueue_struct;
struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
struct work_struct {
	struct list_head entry;
	work_func_t func;
	struct workqueue_struct *wq;
	unsigned int state; /* LKPI_WORK_* bits, under the lkpi work lock */
};
struct delayed_work {
	struct work_struct work;
	struct lkpi_timer timer;
	struct workqueue_struct *wq;
};
#define LKPI_WORK_PENDING 1u
#define LKPI_WORK_RUNNING 2u
#define LKPI_WORK_CANCELING 4u
void lkpi_init_work(struct work_struct *w, work_func_t fn);
void lkpi_init_delayed_work(struct delayed_work *w, work_func_t fn);
#define INIT_WORK(w, fn) lkpi_init_work(w, fn)
#define INIT_DELAYED_WORK(w, fn) lkpi_init_delayed_work(w, fn)
#define INIT_DEFERRABLE_WORK INIT_DELAYED_WORK
static inline struct delayed_work *to_delayed_work(struct work_struct *w)
{ return container_of(w, struct delayed_work, work); }
#define WQ_UNBOUND 0x2u
#define WQ_FREEZABLE 0x4u
#define WQ_MEM_RECLAIM 0x8u
#define WQ_HIGHPRI 0x10u
#define WQ_BH 0x1u
#define WQ_PERCPU 0x100u
struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...);
#define alloc_ordered_workqueue(fmt, flags, ...) alloc_workqueue(fmt, flags, 1, ##__VA_ARGS__)
/* ordered queue whose worker holds @lock around every item (wiphy work) */
struct workqueue_struct *lkpi_alloc_wq_locked(const char *name, struct mutex *lock);
void destroy_workqueue(struct workqueue_struct *wq);
void flush_workqueue(struct workqueue_struct *wq);
#define drain_workqueue flush_workqueue
extern struct workqueue_struct *system_wq;
bool queue_work(struct workqueue_struct *wq, struct work_struct *w);
bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *w, unsigned long delay);
bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *w, unsigned long delay);
#define schedule_work(w) queue_work(system_wq, w)
#define schedule_delayed_work(w, d) queue_delayed_work(system_wq, w, d)
bool cancel_work(struct work_struct *w);
bool cancel_work_sync(struct work_struct *w);
bool cancel_delayed_work(struct delayed_work *w);
bool cancel_delayed_work_sync(struct delayed_work *w);
bool flush_work(struct work_struct *w);
bool flush_delayed_work(struct delayed_work *w);
bool work_pending(struct work_struct *w);
#define delayed_work_pending(w) work_pending(&(w)->work)
void lkpi_timer_add(struct lkpi_timer *t, u64 delay_ns);
bool lkpi_timer_del(struct lkpi_timer *t);

/* ---------- device model stubs ---------- */
struct pci_dev;
struct kobject { int unused; };
struct device_driver { const char *name; };
struct device {
	struct kobject kobj;
	struct device *parent;
	void *driver_data;
	const char *init_name;
	const struct attribute_group **groups;
};
static inline struct device *kobj_to_dev(struct kobject *k) { return container_of(k, struct device, kobj); }
static inline void *dev_get_drvdata(const struct device *d) { return d->driver_data; }
static inline void dev_set_drvdata(struct device *d, void *p) { d->driver_data = p; }
static inline const char *dev_name(const struct device *d) { return d->init_name ? d->init_name : "rtw89"; }
static inline int device_set_wakeup_enable(struct device *d, bool en) { return 0; }
static inline bool device_can_wakeup(struct device *d) { return false; }
static inline bool device_may_wakeup(struct device *d) { return false; }
struct attribute { const char *name; umode_t mode; };
struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *dev, struct device_attribute *attr, char *buf);
	ssize_t (*store)(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
};
struct attribute_group {
	const char *name;
	struct attribute **attrs;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
};
#define DEVICE_ATTR_RO(_name) struct device_attribute dev_attr_##_name = { .attr = { .name = #_name, .mode = 0444 }, .show = _name##_show }
#define SYSFS_GROUP_VISIBLE(fn) sysfs_group_visible_##fn
#define DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(name) \
	static inline umode_t sysfs_group_visible_##name(struct kobject *kobj, struct attribute *attr, int n) \
	{ return name##_group_visible(kobj) ? attr->mode : 0; }
#define ATTRIBUTE_GROUPS(name) \
	static const struct attribute_group name##_group = { .attrs = name##_attrs }; \
	static const struct attribute_group *name##_groups[] = { &name##_group, NULL }
#define __ATTRIBUTE_GROUPS(name) \
	static const struct attribute_group *name##_groups[] = { &name##_group, NULL }

/* ---------- firmware ---------- */
struct firmware { size_t size; const u8 *data; };
int request_firmware(const struct firmware **fw, const char *name, struct device *dev);
int firmware_request_nowarn(const struct firmware **fw, const char *name, struct device *dev);
void release_firmware(const struct firmware *fw);

/* ---------- dmi / acpi / uuid / coredump / debugfs: absent on this host ---------- */
struct dmi_system_id { const char *ident; void *driver_data; };
static inline const struct dmi_system_id *dmi_first_match(const struct dmi_system_id *l) { return NULL; }
#define DMI_MATCH(a, b) { }
typedef struct { u8 b[16]; } guid_t;
typedef struct { u8 b[16]; } uuid_t;
#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) ((guid_t){ { \
	(a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
	(b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff, \
	(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } })
typedef void *acpi_handle;
typedef u32 acpi_status;
typedef char *acpi_string;
typedef u64 acpi_size;
#define AE_OK 0
#define AE_NOT_FOUND 5
#define ACPI_FAILURE(s) ((s) != AE_OK)
#define ACPI_SUCCESS(s) ((s) == AE_OK)
#define ACPI_ALLOCATE_BUFFER ((acpi_size)-1)
#define ACPI_TYPE_INTEGER 1
#define ACPI_TYPE_STRING 2
#define ACPI_TYPE_BUFFER 3
#define ACPI_TYPE_PACKAGE 4
union acpi_object {
	u32 type;
	struct { u32 type; u64 value; } integer;
	struct { u32 type; u32 length; char *pointer; } string;
	struct { u32 type; u32 length; u8 *pointer; } buffer;
	struct { u32 type; u32 count; union acpi_object *elements; } package;
};
struct acpi_buffer { acpi_size length; void *pointer; };
struct acpi_object_list { u32 count; union acpi_object *pointer; };
#define ACPI_HANDLE(dev) ((acpi_handle)NULL)
#define ACPI_FREE(p) kfree(p)
static inline acpi_status acpi_get_handle(acpi_handle p, acpi_string n, acpi_handle *h) { return AE_NOT_FOUND; }
static inline acpi_status acpi_evaluate_object(acpi_handle h, acpi_string n, struct acpi_object_list *a, struct acpi_buffer *b) { return AE_NOT_FOUND; }
static inline union acpi_object *acpi_evaluate_dsm(acpi_handle h, const guid_t *g, u64 rev, u64 func, union acpi_object *argv4) { return NULL; }
static inline void dev_coredumpv(struct device *dev, void *data, size_t len, gfp_t gfp) { vfree(data); }
struct dentry;
struct file;
struct file_operations { int unused; };
static inline struct dentry *debugfs_create_dir(const char *n, struct dentry *p) { return NULL; }
static inline struct dentry *debugfs_create_file(const char *n, umode_t m, struct dentry *p, void *d, const struct file_operations *f) { return NULL; }

/* ---------- networking ---------- */
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86DD
#define ETH_P_PAE 0x888E
#define ETH_P_TDLS 0x890D
#define ETH_P_802_3 0x0001
#define ETH_P_80221 0x8917
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define NET_SKB_PAD 64
#define NETDEV_ALIGN 32
struct ethhdr { u8 h_dest[ETH_ALEN]; u8 h_source[ETH_ALEN]; __be16 h_proto; } __packed;
struct iphdr {
	u8 ihl:4, version:4;
	u8 tos; __be16 tot_len; __be16 id; __be16 frag_off; u8 ttl; u8 protocol;
	__sum16 check; __be32 saddr; __be32 daddr;
};
struct udphdr { __be16 source; __be16 dest; __be16 len; __sum16 check; };
struct arphdr { __be16 ar_hrd; __be16 ar_pro; u8 ar_hln; u8 ar_pln; __be16 ar_op; };
static inline bool is_zero_ether_addr(const u8 *a) { return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]); }
static inline bool is_multicast_ether_addr(const u8 *a) { return a[0] & 1; }
static inline bool is_broadcast_ether_addr(const u8 *a) { return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xff; }
static inline bool is_unicast_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a); }
static inline bool is_valid_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a) && !is_zero_ether_addr(a); }
static inline void eth_zero_addr(u8 *a) { memset(a, 0, ETH_ALEN); }
static inline void eth_broadcast_addr(u8 *a) { memset(a, 0xff, ETH_ALEN); }
static inline void ether_addr_copy(u8 *d, const u8 *s) { memcpy(d, s, ETH_ALEN); }
static inline bool ether_addr_equal(const u8 *a, const u8 *b) { return !memcmp(a, b, ETH_ALEN); }
void eth_random_addr(u8 *a);
static inline u32 get_random_u32(void) { return arc4random(); }
static inline u8 get_random_u8(void) { return (u8)arc4random(); }
static inline void get_random_bytes(void *b, size_t n) { arc4random_buf(b, n); }
static inline void get_random_mask_addr(u8 *buf, const u8 *addr, const u8 *mask)
{
	u8 r[ETH_ALEN];
	arc4random_buf(r, ETH_ALEN);
	for (int i = 0; i < ETH_ALEN; i++)
		buf[i] = (addr[i] & mask[i]) | (r[i] & ~mask[i]);
	buf[0] &= ~1; /* unicast */
	buf[0] |= 2;  /* locally administered */
}

struct net_device { char name[16]; void *priv; };
struct napi_struct { struct net_device *dev; int (*poll)(struct napi_struct *, int); int weight; unsigned long state; };
struct net_device *alloc_netdev_dummy(int sizeof_priv);
void free_netdev(struct net_device *dev);
static inline void *netdev_priv(const struct net_device *d) { return d->priv; }
#define NAPI_POLL_WEIGHT 64
void netif_napi_add(struct net_device *dev, struct napi_struct *napi, int (*poll)(struct napi_struct *, int));
static inline void netif_napi_del(struct napi_struct *n) { }
static inline void napi_enable(struct napi_struct *n) { }
static inline void napi_disable(struct napi_struct *n) { }
static inline void napi_synchronize(struct napi_struct *n) { }
static inline bool napi_is_scheduled(struct napi_struct *n) { return false; }
void napi_schedule(struct napi_struct *n);
static inline bool napi_complete_done(struct napi_struct *n, int done) { return true; }
static inline void napi_gro_flush(struct napi_struct *n, bool old) { }

/* sk_buff: linear buffer only */
struct sk_buff {
	struct sk_buff *next, *prev;
	unsigned int len;
	u8 *head, *data, *tail, *end;
	u32 priority;
	__be16 protocol;
	u16 queue_mapping;
	u16 mac_header, network_header, transport_header;
	void *dev;
	char cb[48] __aligned(8);
};
struct sk_buff_head {
	struct sk_buff *next, *prev;
	u32 qlen;
	spinlock_t lock;
};
struct sk_buff *alloc_skb(unsigned int size, gfp_t gfp);
#define dev_alloc_skb(n) ({ struct sk_buff *_s = alloc_skb((n) + NET_SKB_PAD, GFP_ATOMIC); if (_s) skb_reserve(_s, NET_SKB_PAD); _s; })
void kfree_skb(struct sk_buff *skb);
#define dev_kfree_skb(s) kfree_skb(s)
#define dev_kfree_skb_any(s) kfree_skb(s)
#define dev_kfree_skb_irq(s) kfree_skb(s)
#define consume_skb(s) kfree_skb(s)
struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp);
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp);
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp);
static inline unsigned int skb_headroom(const struct sk_buff *s) { return s->data - s->head; }
static inline int skb_tailroom(const struct sk_buff *s) { return s->end - s->tail; }
static inline void skb_reserve(struct sk_buff *s, int n) { s->data += n; s->tail += n; }
static inline void *skb_put(struct sk_buff *s, unsigned int n)
{ u8 *t = s->tail; BUG_ON(s->tail + n > s->end); s->tail += n; s->len += n; return t; }
static inline void *skb_put_zero(struct sk_buff *s, unsigned int n) { void *p = skb_put(s, n); memset(p, 0, n); return p; }
static inline void *skb_put_data(struct sk_buff *s, const void *d, unsigned int n) { void *p = skb_put(s, n); memcpy(p, d, n); return p; }
static inline void skb_put_u8(struct sk_buff *s, u8 v) { *(u8 *)skb_put(s, 1) = v; }
static inline void *skb_push(struct sk_buff *s, unsigned int n) { BUG_ON(s->data - n < s->head); s->data -= n; s->len += n; return s->data; }
static inline void *__skb_push(struct sk_buff *s, unsigned int n) { return skb_push(s, n); }
static inline void *skb_pull(struct sk_buff *s, unsigned int n)
{ if (n > s->len) return NULL; s->len -= n; s->data += n; return s->data; }
static inline void *__skb_pull(struct sk_buff *s, unsigned int n) { return skb_pull(s, n); }
static inline void skb_trim(struct sk_buff *s, unsigned int n) { if (s->len > n) { s->len = n; s->tail = s->data + n; } }
static inline void __skb_trim(struct sk_buff *s, unsigned int n) { skb_trim(s, n); }
static inline void skb_reset_tail_pointer(struct sk_buff *s) { s->tail = s->data; }
static inline void skb_set_tail_pointer(struct sk_buff *s, int off) { s->tail = s->data + off; }
static inline u8 *skb_tail_pointer(const struct sk_buff *s) { return s->tail; }
static inline void skb_reset_mac_header(struct sk_buff *s) { s->mac_header = s->data - s->head; }
static inline void skb_reset_network_header(struct sk_buff *s) { s->network_header = s->data - s->head; }
static inline void skb_set_network_header(struct sk_buff *s, int off) { s->network_header = s->data - s->head + off; }
static inline void skb_set_transport_header(struct sk_buff *s, int off) { s->transport_header = s->data - s->head + off; }
static inline u8 *skb_mac_header(const struct sk_buff *s) { return s->head + s->mac_header; }
static inline u8 *skb_network_header(const struct sk_buff *s) { return s->head + s->network_header; }
static inline u8 *skb_transport_header(const struct sk_buff *s) { return s->head + s->transport_header; }
static inline struct iphdr *ip_hdr(const struct sk_buff *s) { return (struct iphdr *)skb_network_header(s); }
static inline struct udphdr *udp_hdr(const struct sk_buff *s) { return (struct udphdr *)skb_transport_header(s); }
static inline struct ethhdr *eth_hdr(const struct sk_buff *s) { return (struct ethhdr *)skb_mac_header(s); }
static inline bool skb_is_nonlinear(const struct sk_buff *s) { return false; }
static inline int skb_linearize(struct sk_buff *s) { return 0; }
static inline void skb_get_queue_mapping_set(struct sk_buff *s, u16 q) { s->queue_mapping = q; }
#define skb_get_queue_mapping(s) ((s)->queue_mapping)
#define skb_set_queue_mapping(s, q) ((s)->queue_mapping = (q))
static inline void skb_queue_head_init(struct sk_buff_head *l)
{ l->next = l->prev = (struct sk_buff *)l; l->qlen = 0; spin_lock_init(&l->lock); }
static inline void __skb_queue_head_init(struct sk_buff_head *l)
{ l->next = l->prev = (struct sk_buff *)l; l->qlen = 0; }
static inline u32 skb_queue_len(const struct sk_buff_head *l) { return READ_ONCE(l->qlen); }
static inline bool skb_queue_empty(const struct sk_buff_head *l) { return l->next == (const struct sk_buff *)l; }
static inline struct sk_buff *skb_peek(const struct sk_buff_head *l)
{ struct sk_buff *s = l->next; return s == (const struct sk_buff *)l ? NULL : s; }
static inline struct sk_buff *skb_peek_tail(const struct sk_buff_head *l)
{ struct sk_buff *s = l->prev; return s == (const struct sk_buff *)l ? NULL : s; }
static inline void __skb_insert(struct sk_buff *n, struct sk_buff *p, struct sk_buff *nx, struct sk_buff_head *l)
{ n->next = nx; n->prev = p; nx->prev = n; p->next = n; l->qlen++; }
static inline void __skb_queue_tail(struct sk_buff_head *l, struct sk_buff *n) { __skb_insert(n, l->prev, (struct sk_buff *)l, l); }
static inline void __skb_queue_head(struct sk_buff_head *l, struct sk_buff *n) { __skb_insert(n, (struct sk_buff *)l, l->next, l); }
static inline void __skb_unlink(struct sk_buff *s, struct sk_buff_head *l)
{ l->qlen--; s->next->prev = s->prev; s->prev->next = s->next; s->next = s->prev = NULL; }
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *l)
{ struct sk_buff *s = skb_peek(l); if (s) __skb_unlink(s, l); return s; }
static inline void skb_queue_tail(struct sk_buff_head *l, struct sk_buff *n) { spin_lock(&l->lock); __skb_queue_tail(l, n); spin_unlock(&l->lock); }
static inline void skb_queue_head(struct sk_buff_head *l, struct sk_buff *n) { spin_lock(&l->lock); __skb_queue_head(l, n); spin_unlock(&l->lock); }
static inline struct sk_buff *skb_dequeue(struct sk_buff_head *l)
{ spin_lock(&l->lock); struct sk_buff *s = __skb_dequeue(l); spin_unlock(&l->lock); return s; }
static inline void skb_unlink(struct sk_buff *s, struct sk_buff_head *l) { spin_lock(&l->lock); __skb_unlink(s, l); spin_unlock(&l->lock); }
static inline void __skb_queue_purge(struct sk_buff_head *l) { struct sk_buff *s; while ((s = __skb_dequeue(l))) kfree_skb(s); }
static inline void skb_queue_purge(struct sk_buff_head *l) { struct sk_buff *s; while ((s = skb_dequeue(l))) kfree_skb(s); }
static inline void __skb_queue_splice(const struct sk_buff_head *l, struct sk_buff *p, struct sk_buff *n)
{ struct sk_buff *f = l->next, *t = l->prev; f->prev = p; p->next = f; t->next = n; n->prev = t; }
static inline void skb_queue_splice(const struct sk_buff_head *l, struct sk_buff_head *h)
{ if (!skb_queue_empty(l)) { __skb_queue_splice(l, (struct sk_buff *)h, h->next); h->qlen += l->qlen; } }
static inline void skb_queue_splice_init(struct sk_buff_head *l, struct sk_buff_head *h)
{ if (!skb_queue_empty(l)) { __skb_queue_splice(l, (struct sk_buff *)h, h->next); h->qlen += l->qlen; __skb_queue_head_init(l); } }
static inline void skb_queue_splice_tail_init(struct sk_buff_head *l, struct sk_buff_head *h)
{ if (!skb_queue_empty(l)) { __skb_queue_splice(l, h->prev, (struct sk_buff *)h); h->qlen += l->qlen; __skb_queue_head_init(l); } }
#define skb_queue_walk(q, s) for (s = (q)->next; s != (struct sk_buff *)(q); s = s->next)
#define skb_queue_walk_safe(q, s, t) \
	for (s = (q)->next, t = s->next; s != (struct sk_buff *)(q); s = t, t = s->next)

/* linux/average.h */
#define DECLARE_EWMA(name, _precision, _weight_rcp) \
struct ewma_##name { unsigned long internal; }; \
static inline void ewma_##name##_init(struct ewma_##name *e) { e->internal = 0; } \
static inline unsigned long ewma_##name##_read(struct ewma_##name *e) { return READ_ONCE(e->internal) >> (_precision); } \
static inline void ewma_##name##_add(struct ewma_##name *e, unsigned long val) \
{ \
	unsigned long in = READ_ONCE(e->internal), w = ilog2(_weight_rcp); \
	WRITE_ONCE(e->internal, in ? (((in << w) - in) + (val << (_precision))) >> w : (val << (_precision))); \
}

#endif /* LKPI_H */

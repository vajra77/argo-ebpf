#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

/* Helper per Mappe eBPF (Sintassi moderna BTF) */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

/* Definizione dei prototipi eBPF indispensabili */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *) 5;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *) 132;

#endif
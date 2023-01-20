#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <uapi/linux/btf.h>
#include <linux/rcupdate_trace.h>
#include <linux/btf_ids.h>

#include "map_in_map.h"

#define ARRAY_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_ACCESS_MASK | \
	 BPF_F_PRESERVE_ELEMS | BPF_F_INNER_MAP)

static void bpf_array_free_percpu(struct bpf_array *array)
{
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		free_percpu(array->pptrs[i]);
		cond_resched();
	}
}

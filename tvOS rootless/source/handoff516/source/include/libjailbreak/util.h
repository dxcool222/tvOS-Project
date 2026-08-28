#ifndef LJB_UTIL_H
#define LJB_UTIL_H

#include "info.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

void proc_iterate(void (^itBlock)(uint64_t, bool *));

uint64_t proc_self(void);
uint64_t task_self(void);
uint64_t vm_map_self(void);
uint64_t pmap_self(void);
uint64_t ttep_self(void);
uint64_t tte_self(void);

uint64_t task_get_ipc_port_table_entry(uint64_t task, mach_port_t port);
uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

uint64_t alloc_page_table_unassigned(void);
uint64_t pmap_alloc_page_table(uint64_t pmap, uint64_t va);
int pmap_expand_range(uint64_t pmap, uint64_t vaStart, uint64_t size);
int pmap_map_in(uint64_t pmap, uint64_t uaStart, uint64_t paStart, uint64_t size);

void thread_caffeinate_start(void);
void thread_caffeinate_stop(void);

#endif

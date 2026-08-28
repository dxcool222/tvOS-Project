#ifndef KALLOC_PT_H
#define KALLOC_PT_H

#include <stdbool.h>

void libjailbreak_kalloc_pt_init(void);
bool kalloc_pt_is_initialized(void);
unsigned kalloc_pt_pool_count(void);
int kalloc_pt_prefill(unsigned count);

#endif

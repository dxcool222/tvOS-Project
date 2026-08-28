#include <stdint.h>
#include "primitives.h"

// tvOS 16.5 20L563 _proc_task: if (proc+0x458 & 2) return proc+0x720.
uint64_t proc_task(uint64_t proc)
{
    if (!proc) {
        return 0;
    }
    if ((kread8(proc + 0x458) & 2) == 0) {
        return 0;
    }
    return proc + 0x720;
}

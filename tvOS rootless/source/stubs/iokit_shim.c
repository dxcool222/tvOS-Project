#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdint.h>

typedef mach_port_t io_connect_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_object_t;
typedef io_object_t io_iterator_t;

#define IO_OBJECT_NULL ((io_object_t)0)

kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCntP)
{
    (void)connection; (void)selector; (void)input; (void)inputCnt;
    (void)inputStruct; (void)inputStructCnt; (void)output; (void)outputCnt;
    (void)outputStruct; (void)outputStructCntP;
    return KERN_FAILURE;
}

kern_return_t IOServiceClose(io_service_t service)
{
    (void)service;
    return KERN_FAILURE;
}

io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching)
{
    (void)masterPort; (void)matching;
    return IO_OBJECT_NULL;
}

CFMutableDictionaryRef IOServiceMatching(const char *name)
{
    (void)name;
    return NULL;
}

kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect)
{
    (void)service; (void)owningTask; (void)type;
    if (connect) *connect = IO_OBJECT_NULL;
    return KERN_FAILURE;
}

const mach_port_t kIOMasterPortDefault = 0;

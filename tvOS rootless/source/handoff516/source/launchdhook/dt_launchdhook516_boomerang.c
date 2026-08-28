#include <dlfcn.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver_boomerang.h>
#include <unistd.h>

typedef kern_return_t (*dt_mach_ports_lookup_fn)(mach_port_t, mach_port_array_t *,
    mach_msg_type_number_t *);
typedef kern_return_t (*dt_mach_ports_register_fn)(mach_port_t, mach_port_array_t,
    mach_msg_type_number_t);

static dt_mach_ports_lookup_fn dt_mach_ports_lookup;
static dt_mach_ports_register_fn dt_mach_ports_register;

__attribute__((constructor)) static void dt_boomerang516_init(void)
{
    dt_mach_ports_lookup =
        (dt_mach_ports_lookup_fn)dlsym(RTLD_DEFAULT, "mach_ports_lookup");
    dt_mach_ports_register =
        (dt_mach_ports_register_fn)dlsym(RTLD_DEFAULT, "mach_ports_register");
}

int boomerang_recoverPrimitives516(bool firstRetrieval, bool shouldEndBoomerang)
{
    if (!dt_mach_ports_lookup || !dt_mach_ports_register)
        return -100;

    mach_port_t *registeredPorts = NULL;
    mach_msg_type_number_t registeredPortsCount = 0;
    if (dt_mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 ||
        registeredPortsCount < 3) {
        return -1;
    }
    mach_port_t boomerangPort = registeredPorts[2];
    if (boomerangPort == MACH_PORT_NULL)
        return -2;

    jbclient_xpc_set_custom_port(boomerangPort);
    registeredPorts[2] = MACH_PORT_NULL;
    dt_mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

    bool physrwPTE = firstRetrieval && !is_kcall_available();
    int r = jbclient_initialize_primitives_internal(physrwPTE);
    if (r != 0)
        return r;

    if (shouldEndBoomerang)
        jbclient_boomerang_done();
    return 0;
}

#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <dlfcn.h>
#include <unistd.h>

typedef kern_return_t (*dt681_mpl_fn)(mach_port_t, mach_port_name_array_t *, mach_msg_type_number_t *);
typedef kern_return_t (*dt681_mpr_fn)(mach_port_t, mach_port_name_array_t, mach_msg_type_number_t);
typedef kern_return_t (*dt681_tfp_fn)(mach_port_t, pid_t, mach_port_t *);

static dt681_mpl_fn g_mpl;
static dt681_mpr_fn g_mpr;
static dt681_tfp_fn g_tfp;

static void dt681_jbctl_stage(const char *marker)
{
    fprintf(stderr, "STAGE %s\n", marker);
}

static void dt681_jbctl_log_kr(const char *op, kern_return_t kr)
{
    const char *err = mach_error_string(kr);
    fprintf(stderr, "%s kr=0x%x (%s)\n", op, kr, err ? err : "?");
}

static void dt681_jbctl_init(void)
{
    void *lib = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW);
    if (!lib)
        return;
    g_mpl = (dt681_mpl_fn)dlsym(lib, "mach_ports_lookup");
    g_mpr = (dt681_mpr_fn)dlsym(lib, "mach_ports_register");
    g_tfp = (dt681_tfp_fn)dlsym(lib, "task_for_pid");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    dt681_jbctl_init();
    if (!g_mpl || !g_mpr || !g_tfp) {
        fprintf(stderr, "ERROR: missing Mach/spawn shims\n");
        return 1;
    }

    mach_port_name_array_t selfInitPorts = NULL;
    mach_msg_type_number_t selfInitPortsCount = 0;
    kern_return_t kr = g_mpl(mach_task_self(), &selfInitPorts, &selfInitPortsCount);
    if (kr != KERN_SUCCESS) {
        dt681_jbctl_log_kr("ERROR: mach_ports_lookup self failed", kr);
        return 2;
    }
    if (selfInitPortsCount < 3 || selfInitPorts[2] == MACH_PORT_NULL) {
        fprintf(stderr, "ERROR: Port to stash not set count=%u\n", selfInitPortsCount);
        return 3;
    }

    dt681_jbctl_stage("KCALL681_JBCTL_LOOKUP_SELF_OK");
    fprintf(stderr, "Port to stash: %u\n", selfInitPorts[2]);

    mach_port_t launchdTaskPort = MACH_PORT_NULL;
    kr = g_tfp(mach_task_self(), 1, &launchdTaskPort);
    if (kr != KERN_SUCCESS) {
        dt681_jbctl_log_kr("task_for_pid on launchd failed", kr);
        return 4;
    }
    dt681_jbctl_stage("KCALL681_JBCTL_TFP1_OK");

    mach_port_name_array_t launchdInitPorts = NULL;
    mach_msg_type_number_t launchdInitPortsCount = 0;
    kr = g_mpl(launchdTaskPort, &launchdInitPorts, &launchdInitPortsCount);
    if (kr != KERN_SUCCESS) {
        dt681_jbctl_log_kr("mach_ports_lookup on launchd failed", kr);
        mach_port_deallocate(mach_task_self(), launchdTaskPort);
        return 5;
    }
    if (launchdInitPortsCount < 3) {
        fprintf(stderr, "ERROR: Unexpected initports count on launchd count=%u\n",
            launchdInitPortsCount);
        mach_port_deallocate(mach_task_self(), launchdTaskPort);
        return 6;
    }
    dt681_jbctl_stage("KCALL681_JBCTL_LOOKUP_LAUNCHD_OK");

    launchdInitPorts[2] = selfInitPorts[2];
    kr = g_mpr(launchdTaskPort, launchdInitPorts, launchdInitPortsCount);
    if (kr != KERN_SUCCESS) {
        dt681_jbctl_log_kr("mach_ports_register on launchd failed", kr);
        mach_port_deallocate(mach_task_self(), launchdTaskPort);
        return 7;
    }
    dt681_jbctl_stage("KCALL681_JBCTL_MPR_OK");

    mach_port_deallocate(mach_task_self(), launchdTaskPort);
    return 0;
}

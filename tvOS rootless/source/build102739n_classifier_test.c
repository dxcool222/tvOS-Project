#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

enum result { SAME_BOOT_AWAITING_REBOOT, DIFFERENT_KERNEL_BOOT_CONFIRMED,
    BOOT_IDENTITY_AMBIGUOUS };

static enum result classify(bool valid, bool uuid_equal, bool time_equal)
{
    if (!valid || uuid_equal != time_equal) return BOOT_IDENTITY_AMBIGUOUS;
    return uuid_equal ? SAME_BOOT_AWAITING_REBOOT : DIFFERENT_KERNEL_BOOT_CONFIRMED;
}

int main(void)
{
    assert(classify(true, true, true) == SAME_BOOT_AWAITING_REBOOT);
    assert(classify(true, false, false) == DIFFERENT_KERNEL_BOOT_CONFIRMED);
    assert(classify(true, true, false) == BOOT_IDENTITY_AMBIGUOUS);
    assert(classify(true, false, true) == BOOT_IDENTITY_AMBIGUOUS);
    assert(classify(false, true, true) == BOOT_IDENTITY_AMBIGUOUS);
    assert(classify(false, false, false) == BOOT_IDENTITY_AMBIGUOUS);
    puts("BUILD102739N_BOOT_IDENTITY_CLASSIFIER_HOST_VECTORS=PASS");
    return 0;
}

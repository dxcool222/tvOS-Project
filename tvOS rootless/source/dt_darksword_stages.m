#import "dt_darksword_stages.h"
#import "DTRunLogger.h"
#include <stdio.h>

void dt_ds_stage(const char *marker)
{
    if (!marker)
        return;
    printf("%s\n", marker);
    fflush(stdout);
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:marker]];
}

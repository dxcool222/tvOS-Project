#pragma once

#import <Foundation/Foundation.h>

/// misaka/J do_fun() equivalent — kread-only post-kopen verification.
BOOL dt_do_fun(void (^log)(NSString *line));

#include "display.h"

#import <Foundation/Foundation.h>

void wait_vblank_start()
{
    NSDate *const date = [NSDate date];
    [[NSRunLoop mainRunLoop] runUntilDate:date];
}

//
//  AppDelegate.mm
//  VitaEmulator
//
//  Created by Peter Mackay on 02/06/2016.
//  Copyright © 2016 Peter Mackay. All rights reserved.
//

#import "AppDelegate.h"

#include "../emulator/emulator.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    NSArray<NSString *> *args = [NSProcessInfo processInfo].arguments;
    
    const dispatch_block_t block = ^{
        if ((args.count < 2) || !emulate(args[1].UTF8String))
        {
            exit(1);
        }
    };
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0), dispatch_get_main_queue(), block);
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
	// Insert code here to tear down your application
}

@end

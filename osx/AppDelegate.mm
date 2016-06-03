//
//  AppDelegate.mm
//  VitaEmulator
//
//  Created by Peter Mackay on 02/06/2016.
//  Copyright © 2016 Peter Mackay. All rights reserved.
//

#import "AppDelegate.h"

#include <unicorn/unicorn.h>

#include <array>
#include <vector>

@interface AppDelegate ()

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    typedef std::array<uc_engine *, 2> Contexts;
    Contexts ucs;
    for (Contexts::iterator uc = ucs.begin(); uc != ucs.end(); ++uc)
    {
        uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &*uc);
    }
	
	const uint64 address = 4096;
	std::vector<uint8_t> mapped(8192);
    for (uc_engine *uc : ucs)
    {
        uc_mem_map_ptr(uc, address, mapped.size(), UC_PROT_ALL, &mapped.front());
    }
    
	const uint8_t expected = 123;
    uc_mem_write(ucs[0], address, &expected, sizeof(expected));
	
	uint8_t actual = 231;
	uc_mem_read(ucs[1], address, &actual, sizeof(actual));
	
	assert(actual == expected);
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
	// Insert code here to tear down your application
}

@end

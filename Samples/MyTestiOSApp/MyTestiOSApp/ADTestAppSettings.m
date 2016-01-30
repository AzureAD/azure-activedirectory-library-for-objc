// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADTestAppSettings.h"
#import "ADTestInstance.h"

NSString* const sAADTestInstance = @"AAD Instance";

@implementation ADTestAppSettings

-(id) init
{
    self = [super init];
    if (!self)
    {
        return nil;
    }
    
    NSString* path = [[NSBundle mainBundle] pathForResource:@"TestData" ofType:@"plist"];
    if (!path || !path.length)
    {
        return nil;
    }
    
    NSDictionary* all = [NSDictionary dictionaryWithContentsOfFile:path];
    NSMutableDictionary* testAuthorities = [[NSMutableDictionary alloc] initWithCapacity:all.count];
    for(NSDictionary* instanceName in all.allKeys)
    {
        NSDictionary* instanceData = [all objectForKey:instanceName];
        if (!instanceData || ![instanceData isKindOfClass:[NSDictionary class]])
        {
            NSLog(@"Bad data for the instance: '%@'. Contents: %@", instanceName, instanceData);
            continue;
        }
        ADTestInstance* instance = [ADTestInstance getInstance:instanceData];
        [testAuthorities setObject:instance forKey:instanceName];
        break;
    }
    self->_testAuthorities = testAuthorities;
    return self;
}

//Code coverage logic:
#ifdef AD_CODE_COVERAGE
extern void __gcov_flush(void);
-(void) flushCodeCoverage
{
    __gcov_flush();
}
#else
//No-op:
-(void) flushCodeCoverage{}
#endif


@end

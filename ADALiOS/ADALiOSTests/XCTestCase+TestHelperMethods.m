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

#import "ADALiOS.h"
#import "ADLogger.h"
#import "NSString+ADHelperMethods.h"
#import "ADErrorCodes.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationSettings.h"
#import <libkern/OSAtomic.h>
#import <Foundation/NSObjCRuntime.h>
#import <objc/runtime.h>


@implementation XCTestCase (TestHelperMethods)

//Tracks the logged messages.
NSString* const sTestBegin = @"|||TEST_BEGIN|||";
NSString* const sTestEnd = @"|||TEST_END|||";

volatile int sAsyncExecuted;//The number of asynchronous callbacks executed.

/* See header for details.*/
- (void)adValidateFactoryForInvalidArgument:(NSString*)argument
                             returnedObject:(id)returnedObject
                                      error:(ADAuthenticationError*)error
{
    XCTAssertNil(returnedObject, "Creator should have returned nil. Object: %@", returnedObject);
    
    //[self adValidateForInvalidArgument:argument error:error];
}
#ifdef AD_CODE_COVERAGE
extern void __gcov_flush(void);
#endif
-(void) adFlushCodeCoverage
{
#ifdef AD_CODE_COVERAGE
    __gcov_flush();
#endif
}

- (void)adCallAndWaitWithFile:(NSString*)file
                         line:(int)line
                    semaphore:(dispatch_semaphore_t)sem
                        block:(void (^)(void))block
{
    THROW_ON_NIL_ARGUMENT(sem);
    THROW_ON_NIL_EMPTY_ARGUMENT(file);
    THROW_ON_NIL_ARGUMENT(block);
    
    block();//Run the intended asynchronous method
    while (dispatch_semaphore_wait(sem, DISPATCH_TIME_NOW))
    {
        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
}

@end

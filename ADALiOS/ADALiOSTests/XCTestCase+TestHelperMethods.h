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

#import <XCTest/XCTest.h>
#import "../ADALiOS/ADAuthenticationError.h"
#import "../ADALiOS/ADALiOS.h"

@class ADTokenCacheStoreItem;
@class ADProfileInfo;

@interface XCTestCase (HelperMethods)

/*! Used with the class factory methods that create class objects. Verifies
 the expectations when the passed argument is invalid:
 - The creator should return nil.
 - The error should be set accordingly, containing the argument in the description.*/
-(void) adValidateFactoryForInvalidArgument: (NSString*) argument
                           returnedObject: (id) returnedObject
                                    error: (ADAuthenticationError*) error;

/* A special helper, which invokes the 'block' parameter in the UI thread and waits for its internal
 callback block to complete.
 IMPORTANT: The internal callback block should end with ASYNCH_COMPLETE macro to signal its completion. Example:
 static volatile int comletion  = 0;
 [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
 {
    [mAuthenticationContext acquireTokenWithScopes:mScopes
                                     completionBlock:^(ADAuthenticationResult* result)
    {
        //Inner block:
        mResult = result;
        ASYNC_BLOCK_COMPLETE(completion);//Signals the completion
    }];
 }];
 The method executes the block in the UI thread, but runs an internal run loop and thus allows methods which enqueue their
 completion callbacks on the UI thread.
 */
-(void) adCallAndWaitWithFile: (NSString*) file
                         line: (int) line
                    semaphore: (dispatch_semaphore_t) signal
                        block: (void (^)(void)) block;
@end

//Fixes the issue with XCTAssertEqual not comparing int and long values
//Usage: ADAssertLongEquals(5, [self calculateFive]);
#define ADAssertLongEquals(CONST, EXPR) XCTAssertEqual((long)CONST, (long)EXPR)

#define ADAssertThrowsArgument(EXP) \
{ \
    XCTAssertThrowsSpecificNamed((EXP), NSException, NSInvalidArgumentException, "Exception expected for %s", #EXP); \
}

//Fixes the problem with the test framework not able to compare dates:
#define ADAssertDateEquals(actualParam, expectedParam) XCTAssertTrue([expectedParam compare:actualParam] == NSOrderedSame)

//Verifes that "error" local variable is nil. If not prints the error
#define ADAssertNoError XCTAssertNil(error, "Unexpected error occurred: %@", error.errorDetails)

#define ADAssertArgumentError(_argument, _ERROR) { \
    XCTAssertNotNil(_ERROR); \
    if (_ERROR) { \
        XCTAssertEqual(_ERROR.domain, ADInvalidArgumentDomain, "Incorrect error domain."); \
        XCTAssertTrue([_ERROR.errorDetails rangeOfString:_argument options:NSCaseInsensitiveSearch].location != NSNotFound, @"\"%@\" not found in error details.", _argument); \
    } \
}


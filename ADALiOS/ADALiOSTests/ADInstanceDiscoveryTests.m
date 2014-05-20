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
#import "XCTestCase+TestHelperMethods.h"
#import "ADInstanceDiscovery.h"
#import <libkern/OSAtomic.h>
#import <ADALiOS/ADAuthenticationSettings.h>

NSString* const sAlwaysTrusted = @"https://login.windows.net";

//The next set of variables are used for the thread-safety tests.
dispatch_semaphore_t sThreadsCompletedSemaphore;//Signals the completion of all threads
volatile int32_t sNumThreadsDone;//Number of threads that have exited.
const int sMaxTestThreads = 10;//How many threads to spawn
const int sThreadsRunDuration = 3;//The number of seconds to run the threads.
const int sAsyncTimeout = 10;//in seconds

//Test protocol for easier calling of private methods
@protocol TestInstanceDiscovery <NSObject>

-(NSString*) extractHost: (NSString*) authority
           correlationId: (NSUUID*) correlationId
                   error: (ADAuthenticationError* __autoreleasing *) error;
-(BOOL) isAuthorityValidated: (NSString*) authorityHost;
-(void) setAuthorityValidation: (NSString*) authorityHost;

-(void) requestValidationOfAuthority: (NSString*) authority
                                host: (NSString*) authorityHost
                    trustedAuthority: (NSString*) trustedAuthority
                       correlationId: (NSUUID*) correlationId
                     completionBlock: (ADDiscoveryCallback) completionBlock;

@end

//Test category to expose internal methods.
@interface ADInstanceDiscovery(Test)

//Additional methods to extract instance data:
-(NSMutableSet*) getInternalValidatedAuthorities;

@end

//Avoid warnings for incomplete implementation, as the methods are actually implemented, just not in the category:
@implementation ADInstanceDiscovery(Test)


/*! Internal method, not exposed in the header. Used for testing only. */
-(NSSet*) getInternalValidatedAuthorities
{
    return mValidatedAuthorities;
}

@end


@interface ADInstanceDiscoveryTests : XCTestCase
{
    ADInstanceDiscovery* mInstanceDiscovery;
    __weak id<TestInstanceDiscovery> mTestInstanceDiscovery;//Same as above, just casted to the protocol
    NSMutableSet* mValidatedAuthorities;
    //Used for asynchronous calls:
    BOOL mValidated;
    ADAuthenticationError* mError;
    NSSet* mValidatedAuthoritiesCopy;
}

@end

@implementation ADInstanceDiscoveryTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
    mValidated = NO;
    mInstanceDiscovery = [ADInstanceDiscovery sharedInstance];
    mTestInstanceDiscovery = (id<TestInstanceDiscovery>)mInstanceDiscovery;
    mValidatedAuthorities = [mInstanceDiscovery getInternalValidatedAuthorities];
    mValidatedAuthoritiesCopy = mInstanceDiscovery.validatedAuthorities;//Save the state
    XCTAssertNotEqual(mValidatedAuthorities, mValidatedAuthoritiesCopy, "The validatedAuthorities property should return a copy.");
    //Initialized correctly
    XCTAssertNotNil(mValidatedAuthorities);
    XCTAssertTrue([mValidatedAuthorities containsObject:sAlwaysTrusted]);
    //Start clean: remove all validated authorities:
    if (mValidatedAuthorities.count > 1)
    {
        [mValidatedAuthorities removeAllObjects];
        [mValidatedAuthorities addObject:sAlwaysTrusted];
        XCTAssertTrue(mValidatedAuthorities.count == 1);
    }
}

- (void)tearDown
{
    [mValidatedAuthorities addObjectsFromArray:[mValidatedAuthoritiesCopy allObjects]];//Restore the state
    mInstanceDiscovery = nil;
    mValidatedAuthorities = nil;
    [self adTestEnd];
    [super tearDown];
}

- (void)testInitializers
{
    XCTAssertThrows([ADInstanceDiscovery new]);
    XCTAssertThrows([[ADInstanceDiscovery alloc] init]);
}

-(void) testSharedInstance
{
    [self adClearLogs];
    XCTAssertEqualObjects(mInstanceDiscovery, [ADInstanceDiscovery sharedInstance]);
    ADAssertLogsContain(TEST_LOG_INFO, @"sharedInstance");
}

-(void) testGetValidatedAuthorities
{
    //Test the property:
    NSSet* validatedAuthorities = mInstanceDiscovery.validatedAuthorities;
    XCTAssertNotEqual(validatedAuthorities, mValidatedAuthorities);
    XCTAssertEqualObjects(validatedAuthorities, mValidatedAuthorities);
    XCTAssertFalse([validatedAuthorities isKindOfClass:[NSMutableSet class]], "Read-only class should be returned.");
    ADAssertLogsContain(TEST_LOG_INFO, @"getValidatedAuthorities");
    
    //Modify and test again:
    NSString* newAuthority = @"https://testGetValidatedAuthorities.com";
    [mValidatedAuthorities addObject:newAuthority];
    validatedAuthorities = mInstanceDiscovery.validatedAuthorities;
    XCTAssertTrue([validatedAuthorities containsObject:newAuthority]);
}

-(void) testExtractBaseBadAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];

    //Nil:
    ADAuthenticationError* error;
    NSString* result = [mTestInstanceDiscovery extractHost:nil correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;//Cleanup
    
    //Do not pass error object. Make sure error is logged.
    [self adClearLogs];
    result = [mTestInstanceDiscovery extractHost:nil correlationId:nil error:nil];
    XCTAssertNil(result);
    ADAssertLogsContain(TEST_LOG_MESSAGE, "Error");
    ADAssertLogsContain(TEST_LOG_INFO, "authority");
    error = nil;
    
    //White space string:
    result = [mTestInstanceDiscovery extractHost:@"   " correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;
    
    //Invalid URL:
    result = [mTestInstanceDiscovery extractHost:@"a sdfasdfasas;djfasd jfaosjd fasj;" correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;
    
    //Invalid URL scheme (not using SSL):
    result = [mTestInstanceDiscovery extractHost:@"http://login.windows.net" correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;
    
    //Path
    result = [mTestInstanceDiscovery extractHost:@"././login.windows.net" correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;
    
    //Relative URL
    result = [mTestInstanceDiscovery extractHost:@"login" correlationId:nil error:&error];
    XCTAssertNil(result);
    [self adValidateForInvalidArgument:@"authority" error:error];
    error = nil;
}

-(void) testExtractBaseNormal
{
    ADAuthenticationError* error;
    NSString* authority = @"httpS://Login.Windows.Net/MSopentech.onmicrosoft.com/oauth2/authorize";
    NSString* result = [mTestInstanceDiscovery extractHost:authority correlationId:nil error:&error];
    ADAssertNoError;
    ADAssertStringEquals(result, @"https://login.windows.net");
    error = nil;//Cleanup
    
    //End with "/"
    authority = @"httpS://Login.Windows.Net/MSopentech.onmicrosoft.com/oauth2/authorize/";
    result = [mTestInstanceDiscovery extractHost:authority correlationId:nil error:&error];
    ADAssertNoError;
    ADAssertStringEquals(result, @"https://login.windows.net");
    error = nil;
    
    //End with "/" and base only:
    authority = @"httpS://Login.Windows.Net/stuff";
    result = [mTestInstanceDiscovery extractHost:authority correlationId:[NSUUID UUID] error:&error];
    ADAssertNoError;
    ADAssertStringEquals(result, @"https://login.windows.net");
    error = nil;
}

-(void) testIsAuthorityValidated
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    XCTAssertThrows([mTestInstanceDiscovery isAuthorityValidated:nil]);
    XCTAssertThrows([mTestInstanceDiscovery isAuthorityValidated:@"  "]);
    NSString* anotherHost = @"https://somedomain.com";
    XCTAssertFalse([mTestInstanceDiscovery isAuthorityValidated:anotherHost]);
    XCTAssertTrue([mTestInstanceDiscovery isAuthorityValidated:sAlwaysTrusted]);
    [mValidatedAuthorities addObject:anotherHost];
    XCTAssertTrue([mTestInstanceDiscovery isAuthorityValidated:anotherHost]);
}

-(void) testSetAuthorityValidation
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    XCTAssertThrows([mTestInstanceDiscovery setAuthorityValidation:nil]);
    XCTAssertThrows([mTestInstanceDiscovery setAuthorityValidation:@"  "]);
    //Test that re-adding is ok. This can happen in multi-threaded scenarios:
    [mTestInstanceDiscovery setAuthorityValidation:sAlwaysTrusted];
    
    NSString* anotherHost = @"https://another.host.com";
    [mTestInstanceDiscovery setAuthorityValidation:anotherHost];
    XCTAssertTrue([mValidatedAuthorities containsObject:anotherHost]);
}

-(void) threadProc
{
    @autoreleasepool
    {
        const int maxAuthorities = 100;
        NSMutableArray* array = [[NSMutableArray alloc] initWithCapacity:maxAuthorities];
        for (int i = 0; i < maxAuthorities; ++i)
        {
            [array addObject:[NSString stringWithFormat:@"%d", i]];
        }
        NSDate* end = [NSDate dateWithTimeIntervalSinceNow:sThreadsRunDuration];
        NSDate* now;
        do
        {
            @autoreleasepool//The cycle will create constantly objects, so it needs its own autorelease pool
            {
                @synchronized(mInstanceDiscovery)//Use the same lock, as internal implementation
                {
                    [mValidatedAuthorities removeAllObjects];
                }
                
                for(int i = 0; i < maxAuthorities; ++i)
                {
                    //Just add a check objects. Note that the result is not guaranteed due to multiple
                    //threads:
                    [mTestInstanceDiscovery setAuthorityValidation:[array objectAtIndex:i]];
                    [mTestInstanceDiscovery isAuthorityValidated:[array objectAtIndex:i]];
                }
                
                now = [NSDate dateWithTimeIntervalSinceNow:0];
            }
        } while ([end compare:now] == NSOrderedDescending);
        if (OSAtomicIncrement32(&sNumThreadsDone) == sMaxTestThreads)
        {
            dispatch_semaphore_signal(sThreadsCompletedSemaphore);
        }
    }
}

-(void) testMultipleThreads
{
    sThreadsCompletedSemaphore = dispatch_semaphore_create(0);
    XCTAssertTrue(sThreadsCompletedSemaphore, "Cannot create semaphore");

    sNumThreadsDone = 0;
    [ADLogger setLevel:ADAL_LOG_LEVEL_NO_LOG];//Disable to stress better the cache.
    for (int i = 0; i < sMaxTestThreads; ++i)
    {
        [self performSelectorInBackground:@selector(threadProc) withObject:self];
    }
    if (dispatch_semaphore_wait(sThreadsCompletedSemaphore, dispatch_time(DISPATCH_TIME_NOW, (sThreadsRunDuration + 5)*NSEC_PER_SEC)))
    {
        XCTFail("Timed out. The threads did not complete smoothly. If the applicaiton has not crashed, this is an indication of a deadlock.");
    }
}

//Calls the asynchronous "validateAuthority" method and waits for completion.
//Sets the iVars of the test class according to the response. note t
-(void) validateAuthority: (NSString*) authority
            correlationId: (NSUUID*)correlationId
                     line: (int) line
{
    mError = nil;//Reset
    static volatile int completion = 0;//Set to 1 at the end of the callback
    [self adCallAndWaitWithFile:@"" __FILE__ line:line completionSignal:&completion block:^
     {
         [mInstanceDiscovery validateAuthority:authority correlationId:correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
          {
              mValidated = validated;
              mError = error;
              ASYNC_BLOCK_COMPLETE(completion)
          }];
     }];
    
    if (mError)
    {
        if (mValidated)
        {
            [self recordFailureWithDescription:@"'validated' parameter set to true in an error condition." inFile:@"" __FILE__ atLine:line expected:NO];
        }
    }
}

//Does not call the server, just passes invalid authority
-(void) testValidateAuthorityError
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    [self validateAuthority:@"http://invalidscheme.com" correlationId:[NSUUID UUID] line:__LINE__];
    XCTAssertNotNil(mError);
    
    [self validateAuthority:@"https://Invalid URL 2305 8 -0238460-820-386" correlationId:nil line:__LINE__];
    XCTAssertNotNil(mError);
}

//Does not call the server, just leverages the cache:
-(void) testValidateAuthorityCache
{
    [self validateAuthority:[NSString stringWithFormat:@"%@/common", sAlwaysTrusted] correlationId:nil line:__LINE__];
    XCTAssertTrue(mValidated);
    XCTAssertNil(mError);
}

-(void) testCanonicalizeAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Nil or empty:
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:nil]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@""]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"    "]);
    
    //Invalid URL
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"&-23425 5345g"]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"https:///login.windows.Net/foo"], "Bad URL. Three slashes");
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"https:////"]);
    
    //Non-ssl:
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"foo"]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"http://foo"]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"http://www.microsoft.com"]);
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"abcde://login.windows.net/common"]);
    
    //Canonicalization to the supported extent:
    NSString* authority = @"    https://www.microsoft.com/foo.com/";
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:authority], @"https://www.microsoft.com/foo.com");

    authority = @"https://www.microsoft.com/foo.com";
    //Without the trailing "/":
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://www.microsoft.com/foo.com"], authority);
    //Ending with non-white characters:
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://www.microsoft.com/foo.com   "], authority);
    
    authority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    //Test canonicalizing the endpoints:
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Token"], authority);
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Authorize"], authority);
    
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net"], "No tenant");
    XCTAssertNil([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/"], "No tenant");

    //Trimming beyond the tenant:
    authority = @"https://login.windows.net/foo.com";
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/foo.com/bar"], authority);
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/foo.com"], authority);
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/foo.com/"], authority);
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.Net/foo.com#bar"], authority);
    authority = @"https://login.windows.net/common";//Use "common" for a change
    ADAssertStringEquals([ADInstanceDiscovery canonicalizeAuthority:@"https://login.windows.net/common?abc=123&vc=3"], authority);
}

//Tests a real authority
-(void) testNormalFlow
{
    [mValidatedAuthorities removeAllObjects];//Clear, as "login.windows.net" is already cached.
    [self validateAuthority:@"https://Login.Windows.Net/MSOpenTechBV.onmicrosoft.com" correlationId:nil line:__LINE__];
    XCTAssertTrue(mValidated);
    XCTAssertNil(mError);
    XCTAssertTrue([mValidatedAuthorities containsObject:@"https://login.windows.net"]);
    
    //Now hit explicitly non-cached:
    [self validateAuthority:@"https://login.windows-ppe.net/common" correlationId:nil line:__LINE__];
    XCTAssertTrue(mValidated);
    XCTAssertNil(mError);
    XCTAssertTrue([mValidatedAuthorities containsObject:@"https://login.windows-ppe.net"]);

    //Hit the one that was just cached and ensure that no server-side call is attempted:
    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
    dispatch_queue_t savedQueue = settings.dispatchQueue;
    settings.dispatchQueue = nil;//point nowhere, so that any attempt to a server call will crash.
    [self validateAuthority:@"https://login.windows-ppe.net/common" correlationId:[NSUUID UUID] line:__LINE__];
    XCTAssertTrue(mValidated);
    XCTAssertNil(mError);
    XCTAssertTrue([mValidatedAuthorities containsObject:@"https://login.windows-ppe.net"]);
    settings.dispatchQueue = savedQueue;//Restore for the rest of the tests
}

//Ensures that an invalid authority is not approved
-(void) testNonValidatedAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    NSUUID* correlationId = [NSUUID UUID];
    [self validateAuthority:@"https://MyFakeAuthority.com/MSOpenTechBV.onmicrosoft.com" correlationId:correlationId line:__LINE__];
    XCTAssertFalse(mValidated);
    XCTAssertNotNil(mError);
    ADAssertLongEquals(AD_ERROR_AUTHORITY_VALIDATION, mError.code);
    XCTAssertTrue([mError.errorDetails adContainsString:[correlationId UUIDString].lowercaseString]);
}

-(void) testUnreachableServer
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    static volatile int completion = 0;//Set to 1 at the end of the callback
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal:&completion block:^
    {
        [mTestInstanceDiscovery requestValidationOfAuthority:@"https://login.windows.cn/MSOpenTechBV.onmicrosoft.com"
                                                        host:@"https://login.windows.cn"
                                            trustedAuthority:@"https://SomeValidURLButNotExistentInTheNet.com"
                                               correlationId:[NSUUID UUID]
                                             completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             mValidated = validated;
             mError = error;
             ASYNC_BLOCK_COMPLETE(completion);
         }];
    }];
    
    XCTAssertFalse(mValidated);
    XCTAssertNotNil(mError);
}

@end

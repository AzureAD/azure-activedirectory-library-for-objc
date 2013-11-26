// Created by Boris Vidolov on 10/10/13.
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
#import <ADaLiOS/ADAuthenticationContext.h>
#import <ADALiOS/ADDefaultTokenCacheStore.h>
#import "ADTestTokenCacheStore.h"
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>

@interface ADAuthenticationContextTests : XCTestCase
{
@private
    //The source:
    ADAuthenticationContext* mContext;
    ADDefaultTokenCacheStore* mDefaultTokenCache;
    NSString* mAuthority;
    NSString* mResource;
    NSString* mClientId;
    NSURL* mRedirectURL;
    NSString* mUserId;
    ADPromptBehavior mPromptBehavior;
    
    //The results:
    ADAuthenticationError* mError;//The error filled by the result;
    ADAuthenticationResult* mResult;//Result of asynchronous operation;
}

@end

@implementation ADAuthenticationContextTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin];
    mAuthority = @"https://login.windows.net/msopentechbv.onmicrosoft.com/authorize";
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext contextWithAuthority:mAuthority
                                                       error:&error];
    XCTAssertNotNil(mContext, "Cannot create the context in setUp.");
    XCTAssertNil(error, "Error returned: %@", error.errorDetails);
    mRedirectURL = [NSURL URLWithString:@"http://todolistclient/"];
    mClientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";
    mResource = @"http://localhost/TodoListService";
    mUserId = @"boris";
    mDefaultTokenCache = [ADDefaultTokenCacheStore sharedInstance];
    mPromptBehavior = AD_PROMPT_AUTO;
    //Clear the cache between the tests:
    [mDefaultTokenCache removeAll];
}

- (void)tearDown
{
    mContext = nil;//clear, allow deletion between the tests
    mDefaultTokenCache =  nil;

    [self adTestEnd];
    [super tearDown];
}

- (void)testNew
{
    XCTAssertThrows([ADAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

-(void)testParameterlessInit
{
    XCTAssertThrows([[ADAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

/* A wrapper around validateFactoryForInvalidArgument, passing the test class members*/
-(void) validateFactoryForInvalidArgument: (NSString*) argument
                                    error: (ADAuthenticationError*) error
{
    [self validateFactoryForInvalidArgument:argument
                             returnedObject:mContext
                                      error:error];
}

/* Pass bad authority argument - nil, empty string, etc. */
-(void) checkInvalidAuthorityHandling: (NSString*) authority
{
    //Authority only:
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext contextWithAuthority:nil error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority & validate:
    mContext = [ADAuthenticationContext contextWithAuthority:nil validateAuthority:YES error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil validateAuthority:NO error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority and cache store:
    mContext = [ADAuthenticationContext contextWithAuthority:nil tokenCacheStore:nil error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                             tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority, validate and cache store:
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                           validateAuthority:NO //Non-default value.
                                             tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                           validateAuthority:NO
                                             tokenCacheStore:nil
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                           validateAuthority:YES //Non-default value.
                                             tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                           validateAuthority:YES
                                             tokenCacheStore:nil
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:nil
                                           validateAuthority:YES
                                             tokenCacheStore:nil
                                                       error:&error];
    [self validateFactoryForInvalidArgument:@"authority" error:error];
}

/* Tests all of the static creators by passing authority as nil. Appropriate error should be returned in all cases. */
-(void)testInitAuthorityNil
{
    [self checkInvalidAuthorityHandling:nil];
}

-(void)testInitAuthorityEmpty
{
    [self checkInvalidAuthorityHandling:@""];
}

-(void)testInitAuthorityBlank
{
    [self checkInvalidAuthorityHandling:@"      "];
}

-(void) checkContextObjectWithAuthority: (NSString*) authority
                               validate: (BOOL) validate
                        tokenCacheStore: (id<ADTokenCacheStoring>) tokenCacheStore
                                  error: (ADAuthenticationError*) error;
{
    XCTAssertNil(error, "No error should be raised here. Error: %@", error.errorDetails);
    XCTAssertNotNil(mContext, "Context should be valid in this case.");
    ADAssertStringEquals(authority, mContext.authority);
    XCTAssertEqual(validate, mContext.validateAuthority, "Unexpected validate authority value.");
    XCTAssertEqualObjects(tokenCacheStore, mContext.tokenCacheStore, "Unexpected token cache store.");
}

-(void) testProperties
{
    ADAuthenticationError* error;
    NSString* authority = @"https://authority.com/";
    ADTestTokenCacheStore* testStore = [ADTestTokenCacheStore new];
    XCTAssertNotNil(testStore, "Failed to create a test cache store");
    //Minimal creator:
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                    error:error];
    
    //Authority and validation:
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:NO
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                    error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:YES
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:[ADDefaultTokenCacheStore sharedInstance]
                                    error:error];

    //Authority and token cache store:
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                             tokenCacheStore:nil
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];

    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                             tokenCacheStore:testStore
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
    
    //Authority, validate and token cache store:
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:NO
                                             tokenCacheStore:nil
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:nil
                                    error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:NO
                                             tokenCacheStore:testStore
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:testStore
                                    error:error];

    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:YES
                                             tokenCacheStore:nil
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];
    
    mContext = [ADAuthenticationContext contextWithAuthority:authority
                                           validateAuthority:YES
                                             tokenCacheStore:testStore
                                                       error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
}

/* Helper function to fascilitate calling of the asynchronous acquireToken. 
   Uses the ivars of the test class for the arguments.
 */
-(void) callAsynchronousAcquireToken
{
    //The signal to denote completion:
    __block dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block volatile int executed = 0;
    XCTAssertTrue(completed, "Failed to create a semaphore");
    
    [mContext acquireToken:mResource
                  clientId:mClientId
               redirectUri:mRedirectURL
            promptBehavior:mPromptBehavior
                    userId:mUserId
      extraQueryParameters:nil
           completionBlock:^(ADAuthenticationResult *result)
    {
        //Fill in the iVars with the result:
        if (OSAtomicCompareAndSwapInt( 0, 1, &executed))
        {
            mResult = result;
            mError = mResult.error;
            dispatch_semaphore_signal(completed);//Tell the test to move on
        }
        else
        {
            //Intentionally crash the test execution. As this happens on another thread,
            //there is no reliable to ensure that a second call is not made, without just throwing.
            //Note that the test will succeed, but the test run will fail:
            @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"Double calls of acquire token." userInfo:nil];
        }
     }];
    
    //Waits for the callback:
    if (dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 10*NSEC_PER_SEC)))
    {
        XCTFail("Timeout while calling the acquireToken");
    }
    XCTAssertNotNil(mResult, "Result should not be nil.");
    if (mResult && mResult.status != AD_SUCCEEDED)
    {
        XCTAssertNotNil(mError, "Error should be returned if the result did not succeed.");
        //These will be used by the tests to denote success, so we want to make sure that they are not
        //set in case of failure:
        XCTAssertNil(mResult.accessToken);
        XCTAssertNil(mResult.refreshToken);
    }
    if (mResult && mResult.status == AD_SUCCEEDED)
    {
        XCTAssertNil(mError, "Error should be nil on success. Error: %@", mError.errorDetails);
    }
}

-(void) testAcquireTokenBadCompletionBlock
{
    ADAssertThrowsArgument([mContext acquireToken:mResource clientId:mClientId redirectUri:mRedirectURL completionBlock:nil]);
}


-(void) testAcquireTokenBadResource
{
    mResource = nil;
    [self callAsynchronousAcquireToken];
    [self validateForInvalidArgument:@"resource" error:mError];
    
    mResource = @"   ";
    [self callAsynchronousAcquireToken];
    [self validateForInvalidArgument:@"resource" error:mError];
}

-(void) testAcquireTokenBadClientId
{
    mClientId = nil;
    [self callAsynchronousAcquireToken];
    [self validateForInvalidArgument:@"clientId" error:mError];
    
    mClientId = @"    ";
    [self callAsynchronousAcquireToken];
    [self validateForInvalidArgument:@"clientId" error:mError];
}

-(void) addCacheWithToken: (NSString*) accessToken
               refreshToken: (NSString*) refreshToken
                     userId: (NSString*) userId
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = mResource;
    item.authority = mAuthority;
    item.clientId = mClientId;
    item.accessToken = accessToken;
    item.refreshToken = refreshToken;
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    ADAuthenticationError* error;
    if (userId)
    {
        ADUserInformation* info = [ADUserInformation userInformationWithUserId:userId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(info, "Nil user info returned.");
        item.userInformation = info;
    }
    item.tenantId = @"msopentech.com";
    
    [mDefaultTokenCache addOrUpdateItem:item error:&error];
    ADAssertNoError;
}

-(void) testAcquireTokenWithUserCache
{
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil userId:mUserId];
    [self callAsynchronousAcquireToken];
    ADAssertStringEquals(mResult.accessToken, someTokenValue);

    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user value";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    [self callAsynchronousAcquireToken];
    ADAssertStringEquals(mResult.accessToken, someTokenValue);
    
    //Cache a token for another user:
    NSString* anotherUserTokenValue = @"another user token value";
    [self addCacheWithToken:anotherUserTokenValue refreshToken:nil userId:@"another user"];
    [self callAsynchronousAcquireToken];
    ADAssertStringEquals(mResult.accessToken, someTokenValue);
}

//Tests the scenario where we have a cached item with nil user:
-(void) testAcquireTokenWithNilUserCache
{
    mUserId = nil;//Do not pass a user to acquireToken in this test.
    
    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user token";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    [self callAsynchronousAcquireToken];
    ADAssertStringEquals(mResult.accessToken, nilUserTokenValue);
    
    //Adds a cache for a real user:
    NSString* someUserTokenValue = @"Some user token";
    [self addCacheWithToken:someUserTokenValue refreshToken:nil userId:@"some user"];
    [self callAsynchronousAcquireToken];
    XCTAssertEqual(mResult.status, AD_FAILED);
}

//Tests the scenario where more than one users exist in the cache:
-(void) testAcquireTokenWithMultiUserCache
{
    mUserId = nil;//Do not pass a user to acquireToken in this test.
    
    NSString* user1TokenValue = @"user1 token";
    [self addCacheWithToken:user1TokenValue refreshToken:nil userId:@"user1"];
    NSString* user2TokenValue = @"user2 token";
    [self addCacheWithToken:user2TokenValue refreshToken:nil userId:@"user2"];
    
    [self callAsynchronousAcquireToken];
    XCTAssertEqual(mResult.status, AD_FAILED);
    XCTAssertEqual(mResult.error.code, AD_ERROR_MULTIPLE_USERS);
}

-(void) testAcquireTokenWithNoPrompt
{
    mPromptBehavior = AD_PROMPT_NEVER;
    
    //Nothing in the cache, as we cannot prompt for credentials, this should fail:
    [self callAsynchronousAcquireToken];
    XCTAssertEqual(mResult.status, AD_FAILED);
    XCTAssertEqual(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Something in the cache, should work even with AD_PROMPT_NEVER:
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil userId:mUserId];
    [self callAsynchronousAcquireToken];
    ADAssertStringEquals(mResult.accessToken, someTokenValue);
    
    //Expire the cache item:
    NSArray* allItems = [mDefaultTokenCache allItems];
    XCTAssertTrue(allItems.count == 1);
    ADTokenCacheStoreItem* item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    ADAuthenticationError* error;
    [mDefaultTokenCache addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The access token is expired and the refresh token is nil, so it should fail:
    [self callAsynchronousAcquireToken];
    XCTAssertEqual(mResult.status, AD_FAILED);
    XCTAssertEqual(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Now add an item with a fake refresh token:
//Enable these lines after the refreshToken is implemented
//    XCTAssertTrue(mDefaultTokenCache.allItems.count == 0, "Expired items should be removed from the cache");
//    [self addCacheWithToken:someTokenValue refreshToken:@"some refresh token" userId:mUserId];
//    NSArray* allItems = [mDefaultTokenCache allItems];
//    XCTAssertTrue(allItems.count == 1);
//    ADTokenCacheStoreItem* item = [allItems objectAtIndex:0];
//    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
//    ADAuthenticationError* error;
//    [mDefaultTokenCache addOrUpdateItem:item error:&error];//Udpate the cache.
//    ADAssertNoError;
//    //The access token is expired and the refresh token is nil, so it should fail:
//    [self callAsynchronousAcquireToken];
//    XCTAssertEqual(mResult.status, AD_FAILED);
//    XCTAssertEqual(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Put a valid token in the cache, but set context token cache to nil:
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 0, "Expired items should be removed from the cache");
    [self addCacheWithToken:someTokenValue refreshToken:@"some refresh token" userId:mUserId];
    mContext.tokenCacheStore = nil;
    [self callAsynchronousAcquireToken];
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    XCTAssertEqual(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
}

-(void) testCanonicalizeAuthority
{
    //Nil or empty:
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:nil]);
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@""]);
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@"    "]);
    
    //Invalid URL
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@"&-23425 5345g"]);
    
    //Non-ssl:
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@"foo"]);
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@"http://foo"]);
    XCTAssertNil([ADAuthenticationContext canonicalizeAuthority:@"http://www.microsoft.com"]);

    //Canonicalization to the supported extent:
    NSString* authority = @"    https://www.microsoft.com/foo.com/";
    authority = [ADAuthenticationContext canonicalizeAuthority:authority];
    XCTAssertTrue(![NSString isStringNilOrBlank:authority]);
    //Without the trailing "/":
    ADAssertStringEquals([ADAuthenticationContext canonicalizeAuthority:@"https://www.microsoft.com/foo.com"], authority);
    //Ending with non-white characters:
    ADAssertStringEquals([ADAuthenticationContext canonicalizeAuthority:@"https://www.microsoft.com/foo.com   "], authority);

}

@end

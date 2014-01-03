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
#import "HTTPWebRequest.h"
#import "MockHTTPWebRequest.h"
#import "ADTestAuthenticationContext.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"

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

@property (readonly, getter = getTestContext) ADTestAuthenticationContext* testContext;

@end


@implementation ADAuthenticationContextTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin];
    mAuthority = @"https://login.windows.net/msopentechbv.onmicrosoft.com/authorize";
    mDefaultTokenCache = [ADDefaultTokenCacheStore sharedInstance];
    mRedirectURL = [NSURL URLWithString:@"http://todolistclient/"];
    mClientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";
    mResource = @"http://localhost/TodoListService";
    mUserId = @"boris@mmsopentechbv.onmicrosoft.com";
    mPromptBehavior = AD_PROMPT_AUTO;
    ADAuthenticationError* error;
    ADTestAuthenticationContext* testContext = [[ADTestAuthenticationContext alloc] initWithAuthority:mAuthority
                                                                                    validateAuthority:NO
                                                                                      tokenCacheStore:mDefaultTokenCache
                                                                                                error:&error];
    ADAssertNoError;
    XCTAssertNotNil(testContext, "Cannot create the context in setUp.");
    mContext = testContext;
    [testContext->mExpectedRequest1 setObject:OAUTH2_REFRESH_TOKEN forKey:OAUTH2_GRANT_TYPE];
    [testContext->mExpectedRequest1 setObject:mResource forKey:OAUTH2_RESOURCE];
    [testContext->mExpectedRequest1 setObject:mClientId forKey:OAUTH2_CLIENT_ID];
    
    [testContext->mExpectedRequest2 setObject:OAUTH2_REFRESH_TOKEN forKey:OAUTH2_GRANT_TYPE];
    [testContext->mExpectedRequest2 setObject:mResource forKey:OAUTH2_RESOURCE];
    [testContext->mExpectedRequest2 setObject:mClientId forKey:OAUTH2_CLIENT_ID];
    
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
    NSString* authority = @"https://authority.com/oauth2";
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

-(void) testProtocolSuffix
{
    ADAuthenticationError* error;
    NSString* authority = @"https://authority.com/";
    NSString* expected = @"https://authority.com/oauth2";

    //With ending slash:
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    
    //No ending slash:
    authority = @"https://authority.com";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    
    //With /token:
    authority = @"https://authority.com/token";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    authority = @"https://authority.com/oauth2/token";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    
    //With /authorize
    authority = @"https://authority.com/authorize";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    authority = @"https://authority.com/oauth2/authorize";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    
    //Clear the suffix from the settings, make sure that everything still works:
    [ADAuthenticationSettings sharedInstance].OAuth2ProtocolSuffix = nil;
    authority = @"https://authority.com/token";
    expected = @"https://authority.com";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
    
    [ADAuthenticationSettings sharedInstance].OAuth2ProtocolSuffix = @"";
    mContext = [ADAuthenticationContext contextWithAuthority:authority error:&error];
    ADAssertStringEquals(mContext.authority, expected);
}

#define acquireTokenAsync [self asynchronousAcquireTokenWithLine:__LINE__]
/* Helper function to fascilitate calling of the asynchronous acquireToken. 
   Uses the ivars of the test class for the arguments.
 */
-(void) asynchronousAcquireTokenWithLine: (int) line
{
    //The signal to denote completion:
    __block dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block volatile int executed = 0;
    XCTAssertTrue(completed, "Failed to create a semaphore");
    BOOL isTestContext = [mContext isKindOfClass:[ADTestAuthenticationContext class]];
    if (isTestContext)
    {
        ADTestAuthenticationContext* testContext = (ADTestAuthenticationContext*)mContext;
        testContext->mNumRequests = 0;//Reset to ensure that the number is verified
    }
    
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
        [self recordFailureWithDescription:@"Timeout while calling the acquireToken" inFile:@"" __FILE__ atLine:line expected:NO];
        return;
    }
    XCTAssertNotNil(mResult, "Result should not be nil.");
    if (isTestContext)
    {
        //Handle errors with the expected server communication:
        ADTestAuthenticationContext* testContext = (ADTestAuthenticationContext*)mContext;
        if (testContext->mErrorMessage)
        {
            [self recordFailureWithDescription:testContext->mErrorMessage inFile:@"" __FILE__ atLine:line expected:NO];
            return;
        }
    }
    if (mResult && mResult.status != AD_SUCCEEDED)
    {
        XCTAssertNotNil(mError, "Error should be returned if the result did not succeed.");
        //These will be used by the tests to denote success, so we want to make sure that they are not
        //set in case of failure:
        XCTAssertNil(mResult.tokenCacheStoreItem.accessToken);
        XCTAssertNil(mResult.tokenCacheStoreItem.refreshToken);
    }
    if (mResult && mResult.status == AD_SUCCEEDED)
    {
        XCTAssertNil(mError, "Error should be nil on success. Error: %@", mError.errorDetails);
    }
}

//Local override, using class iVars:
-(ADTokenCacheStoreItem*) createCacheItem
{
    ADTokenCacheStoreItem* item = [super createCacheItem];
    item.resource = mResource;
    item.authority = mAuthority;
    item.clientId = mClientId;
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:mUserId error:&error];
    
    return item;
}

-(void) testAcquireTokenBadCompletionBlock
{
    ADAssertThrowsArgument([mContext acquireToken:mResource clientId:mClientId redirectUri:mRedirectURL completionBlock:nil]);
}


-(void) testAcquireTokenBadResource
{
    mResource = nil;
    acquireTokenAsync;
    [self validateForInvalidArgument:@"resource" error:mError];
    
    mResource = @"   ";
    acquireTokenAsync;
    [self validateForInvalidArgument:@"resource" error:mError];
}

-(void) testAcquireTokenBadClientId
{
    mClientId = nil;
    acquireTokenAsync;
    [self validateForInvalidArgument:@"clientId" error:mError];
    
    mClientId = @"    ";
    acquireTokenAsync;
    [self validateForInvalidArgument:@"clientId" error:mError];
}

-(void) addCacheWithToken: (NSString*) accessToken
             refreshToken: (NSString*) refreshToken
                   userId: (NSString*) userId
                 resource: (NSString*) resource
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = resource;
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
    ADAssertNoError;}

-(void) addCacheWithToken: (NSString*) accessToken
             refreshToken: (NSString*) refreshToken
                   userId: (NSString*) userId
{
    [self addCacheWithToken: accessToken
               refreshToken: refreshToken
                     userId: userId
                   resource: mResource];
}

-(void) addCacheWithToken: (NSString*) accessToken
             refreshToken: (NSString*) refreshToken
{
    [self addCacheWithToken: accessToken
               refreshToken: refreshToken
                     userId: mUserId
                   resource: mResource];
}

-(void) testAcquireTokenWithUserCache
{
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    acquireTokenAsync;
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, someTokenValue);

    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user value";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    acquireTokenAsync;
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, someTokenValue);
    
    //Cache a token for another user:
    NSString* anotherUserTokenValue = @"another user token value";
    [self addCacheWithToken:anotherUserTokenValue refreshToken:nil userId:@"another user"];
    acquireTokenAsync;
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, someTokenValue);
}

//Tests the scenario where we have a cached item with nil user:
-(void) testAcquireTokenWithNilUserCache
{
    mUserId = nil;//Do not pass a user to acquireToken in this test.
    
    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user token";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    acquireTokenAsync;
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, nilUserTokenValue);
    
    //Adds a cache for a real user:
    NSString* someUserTokenValue = @"Some user token";
    [self addCacheWithToken:someUserTokenValue refreshToken:nil userId:@"some user"];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_MULTIPLE_USERS);
}

//Tests the scenario where more than one users exist in the cache:
-(void) testAcquireTokenWithMultiUserCache
{
    mUserId = nil;//Do not pass a user to acquireToken in this test.
    
    NSString* user1 = @"user1";
    NSString* user2 = @"user2";
    NSString* user1TokenValue = @"user1 token";
    [self addCacheWithToken:user1TokenValue refreshToken:nil userId:user1];
    NSString* user2TokenValue = @"user2 token";
    [self addCacheWithToken:user2TokenValue refreshToken:nil userId:user2];
    
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_MULTIPLE_USERS);
    
    //Try the same, but with refresh tokens only:
    [self addCacheWithToken:nil refreshToken:@"refresh1" userId:user1];
    [self addCacheWithToken:nil refreshToken:@"refresh2" userId:user2];
    ADAssertLongEquals(2, mDefaultTokenCache.allItems.count);
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_MULTIPLE_USERS);
}

-(void) testAcquireTokenWithMultiUserBroadTokenCache
{
    mUserId = nil;
    //Try the same, but with refresh tokens only:
    [self addCacheWithToken:nil refreshToken:@"refresh1" userId:@"user1" resource:nil];
    [self addCacheWithToken:nil refreshToken:@"refresh2" userId:@"user2" resource:nil];
    ADAssertLongEquals(2, mDefaultTokenCache.allItems.count);
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_MULTIPLE_USERS);
}

-(ADTestAuthenticationContext*) getTestContext
{
    XCTAssertTrue([mContext isKindOfClass:[ADTestAuthenticationContext class]]);
    return (ADTestAuthenticationContext*)mContext;
}

//Ensures that a cache item with the specified properties exists and returns it if found.
-(ADTokenCacheStoreItem*) verifyCacheWithResource: (NSString*) resource
                                    accessToken: (NSString*) accessToken
                                   refreshToken: (NSString*) refreshToken
                                           line: (int) line
{
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:mAuthority resource:resource clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    
    ADTokenCacheStoreItem* item = [mDefaultTokenCache getItemWithKey:key userId:mUserId];
    if (!item)
    {
        [self recordFailureWithDescription:@"Item not present." inFile:@"" __FILE__ atLine:line expected:NO];
        return nil;
    }
    
    [self assertStringEquals:item.accessToken stringExpression:@"item.accessToken" expected:accessToken file:__FILE__ line:line];
    [self assertStringEquals:item.refreshToken stringExpression:@"item.refreshToken" expected:refreshToken file:__FILE__ line:line];
    return item;
}

-(void) testAcquireTokenWithNoPrompt
{
    mPromptBehavior = AD_PROMPT_NEVER;
    
    //Nothing in the cache, as we cannot prompt for credentials, this should fail:
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Something in the cache, should work even with AD_PROMPT_NEVER:
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    acquireTokenAsync;
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, someTokenValue);
    
    //Expire the cache item:
    NSArray* allItems = [mDefaultTokenCache allItems];
    XCTAssertTrue(allItems.count == 1);
    ADTokenCacheStoreItem* item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    ADAuthenticationError* error;
    [mDefaultTokenCache addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The access token is expired and the refresh token is nil, so it should fail:
    acquireTokenAsync;
    ADAssertLongEquals(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Now add an item with a fake refresh token:
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 0, "Expired items should be removed from the cache");
    NSString* refreshToken = @"some refresh token";
    [self addCacheWithToken:someTokenValue refreshToken:refreshToken];
    allItems = [mDefaultTokenCache allItems];
    XCTAssertTrue(allItems.count == 1);
    item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    [mDefaultTokenCache addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The server error should result in removal of the refresh token from the cache:
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    [self.testContext->mExpectedRequest1 setObject:refreshToken forKey:OAUTH2_REFRESH_TOKEN];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 0, "Bad refresh tokens should be removed from the cache");
    
    //Put a valid token in the cache, but set context token cache to nil:
    [self addCacheWithToken:someTokenValue refreshToken:@"some refresh token"];
    mContext.tokenCacheStore = nil;
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
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

-(void) testGenericErrors
{
    //Refresh token in the cache, but there is no connection to the server. We should not try to open a credentials web view:
    NSString* refreshToken = @"testGenericErrors refresh token";
    [self addCacheWithToken:nil refreshToken:refreshToken];
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 1);
    int errorCode = 42;
    ADAuthenticationError* error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:NSPOSIXErrorDomain code:errorCode userInfo:nil] errorDetails:@"Bad connection"];
    [self.testContext->mExpectedRequest1 setObject:refreshToken forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse1 setObject:error forKey:AUTH_NON_PROTOCOL_ERROR];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the refresh token cannot be used.");
    ADAssertLongEquals(mResult.error.code, errorCode);
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 1, "Nothing should be removed from the cache.");
    
    //Now simulate restoring of the connection and server error, ensure that attempt was made to prompt for credentials:
    mPromptBehavior = AD_PROMPT_NEVER;
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 0, "Bad refresh token should be removed.");
}

-(void) testBroadRefreshTokenSingleUser
{
    //#1: no access token in the cache, however, broad token exists.
    //Broad token is used, but exact refresh token is returned:
    NSString* broadToken = @"testBroadRefreshToken some broad token";
    NSString* accessToken = @"testBroadRefreshToken some access token";
    NSString* exactRefreshToken = @"testBroadRefreshToken exact refresh token";
    [self addCacheWithToken:nil refreshToken:broadToken userId:mUserId resource:nil];
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 1);
    [self.testContext->mExpectedRequest1 setObject:broadToken forKey:OAUTH2_REFRESH_TOKEN];
    //Add both access and refresh token:
    [self.testContext->mResponse1 setObject:accessToken forKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:exactRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    XCTAssertFalse(mResult.multiResourceRefreshToken);
    //Now verify the cache contents for the new broad refresh token and the access token:
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 2);
    ADTokenCacheStoreItem* exactItem = [self verifyCacheWithResource:mResource accessToken:accessToken refreshToken:exactRefreshToken line:__LINE__];
    [self verifyCacheWithResource:nil accessToken:nil refreshToken:broadToken line:__LINE__];
    
    //#2: expire the access token and ensure that the server does not accept the exact refresh token
    //Make sure that both the exact and the refresh tokens are attempted:
    exactItem.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
    ADAuthenticationError* error;
    [mDefaultTokenCache addOrUpdateItem:exactItem error:&error];
    ADAssertNoError;
    //First request should be made with the specific refresh token:
    [self.testContext->mExpectedRequest1 setObject:exactRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    //Error response:
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    //Second request should be made for the broad token, as the first one fails:
    [self.testContext->mExpectedRequest2 setObject:broadToken forKey:OAUTH2_REFRESH_TOKEN];
    self.testContext->mAllowTwoRequests = YES;
    //Respond with another broad token:
    NSString* broadToken2 = @"testBroadRefreshToken another broad token";
    NSString* accessToken2 = @"testBroadRefreshToken another access token";
    [self.testContext->mResponse2 setObject:broadToken2 forKey:OAUTH2_REFRESH_TOKEN];
    //Presence of "resource" denotes multi-resource refresh token:
    [self.testContext->mResponse2 setObject:mResource forKey:OAUTH2_RESOURCE];
    [self.testContext->mResponse2 setObject:accessToken2 forKey:OAUTH2_ACCESS_TOKEN];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    XCTAssertTrue(mResult.multiResourceRefreshToken);
    //Now verify the cache:
    XCTAssertTrue(mDefaultTokenCache.allItems.count == 2);
    [self verifyCacheWithResource:mResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
    [self verifyCacheWithResource:nil accessToken:nil refreshToken:broadToken2 line:__LINE__];
    
    //#3: Use another resource with the broad refresh token. This time do not provide a new refresh token:
    self.testContext->mAllowTwoRequests = NO;
    NSString* oldResource = mResource;
    mResource = @"http://myotherresource";
    [self.testContext->mExpectedRequest1 setObject:mResource forKey:OAUTH2_RESOURCE];//Update the expected resource
    [self.testContext->mExpectedRequest1 setObject:broadToken2 forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_ERROR];
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_REFRESH_TOKEN];
    NSString* accessToken3 = @"yet another access token";
    [self.testContext->mResponse1 setObject:accessToken3 forKey:OAUTH2_ACCESS_TOKEN];
    //Add the resource, but not the refresh token, to cover more edge cases:
    [self.testContext->mResponse1 setObject:mResource forKey:OAUTH2_RESOURCE];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    XCTAssertFalse(mResult.multiResourceRefreshToken);
    ADAssertLongEquals(3, mDefaultTokenCache.allItems.count);
    [self verifyCacheWithResource:oldResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
    [self verifyCacheWithResource:nil accessToken:nil refreshToken:broadToken2 line:__LINE__];
    ADTokenCacheStoreItem* newItem = [self verifyCacheWithResource:mResource accessToken:accessToken3 refreshToken:nil line:__LINE__];
    
    //#4: Now try failing from both the exact and the broad refresh token to ensure that this code path
    //works. Both items should be removed from the cache. Also ensures that the credentials ask is attempted in this case.
    self.testContext->mAllowTwoRequests = YES;
    mPromptBehavior = AD_PROMPT_NEVER;
    newItem.refreshToken = @"new non-working refresh token";
    newItem.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
    [mDefaultTokenCache addOrUpdateItem:newItem error:&error];
    [self.testContext->mExpectedRequest1 setObject:mResource forKey:OAUTH2_RESOURCE];//Update the expected resource
    [self.testContext->mExpectedRequest1 setObject:newItem.refreshToken forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    [self.testContext->mExpectedRequest2 setObject:mResource forKey:OAUTH2_RESOURCE];//Update the expected resource
    [self.testContext->mExpectedRequest2 setObject:broadToken2 forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse2 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    ADAssertNoError;
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED);
    XCTAssertFalse(mResult.multiResourceRefreshToken);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    ADAssertLongEquals(1, mDefaultTokenCache.allItems.count);
    [self verifyCacheWithResource:oldResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
}


-(void) testBroadRefreshTokenMultiUser
{
    //#2: Single user in the cache, exact refresh token available:
//    mUserId = oldUserId;
//    [self addCacheWithToken:nil refreshToken:exactRefreshToken];
//    [self.testContext->mExpectedRequest1 setObject:exactRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
//    //Add both access and refresh token:
//    NSString* accessToken2 = @"another access token";
//    [self.testContext->mResponse1 setObject:accessToken2 forKey:OAUTH2_ACCESS_TOKEN];
//    acquireTokenAsync;
//    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
//    XCTAssertFalse(mResult.multiResourceRefreshToken);
//    ADAssertLongEquals(1, mDefaultTokenCache.allItems.count);
//    [self verifyCacheWithResource:mResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
}

@end

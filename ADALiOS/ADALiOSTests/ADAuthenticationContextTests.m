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
#import "../ADALiOS/ADAuthenticationContext.h"
#import "ADTestTokenCacheStore.h"
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>
#import "ADWebRequest.h"
#import "ADTestAuthenticationContext.h"
#import "../ADALiOS/ADOAuth2Constants.h"
#import "../ADALiOS/ADAuthenticationSettings.h"
#import "../ADALiOS/ADKeychainTokenCacheStore.h"

const int sAsyncContextTimeout = 10;

//A simple protocol to expose private methods:
@protocol ADAuthenticationContextProtocol <NSObject>

-(ADTokenCacheStoreItem*) extractCacheItemWithKey: (ADTokenCacheStoreKey*) key
                                           userId: (NSString*) userId
                                            error: (ADAuthenticationError* __autoreleasing*) error;

-(ADTokenCacheStoreItem*) findCacheItemWithKey: (ADTokenCacheStoreKey*) key
                                        userId: (NSString*) userId
                                useAccessToken: (BOOL*) useAccessToken
                                         error: (ADAuthenticationError* __autoreleasing*) error;
@end

@interface ADAuthenticationContextTests : XCTestCase
{
@private
    //The source:
    ADAuthenticationContext* mContext;
    id<ADAuthenticationContextProtocol> mProtocolContext; //Originally set same as above, provided for simplicity.
    ADKeychainTokenCacheStore* mDefaultTokenCache;
    NSString* mAuthority;
    NSString* mResource;
    NSString* mClientId;
    NSURL* mRedirectURL;
    NSString* mUserId;
    ADPromptBehavior mPromptBehavior;
    BOOL mSilent;
    
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
    [self adTestBegin:ADAL_LOG_LEVEL_ERROR];//Majority of the tests rely on errors
    mAuthority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    mDefaultTokenCache = (ADKeychainTokenCacheStore*)([ADAuthenticationSettings sharedInstance].defaultTokenCacheStore);
    XCTAssertNotNil(mDefaultTokenCache);
    XCTAssertTrue([mDefaultTokenCache isKindOfClass:[ADKeychainTokenCacheStore class]]);
    mRedirectURL = [NSURL URLWithString:@"http://todolistclient/"];
    mClientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";
    mResource = @"http://localhost/TodoListService";
    mUserId = @"boris@msopentechbv.onmicrosoft.com";
    mPromptBehavior = AD_PROMPT_AUTO;
    mSilent = NO;
    ADAuthenticationError* error;
    ADTestAuthenticationContext* testContext = [[ADTestAuthenticationContext alloc] initWithAuthority:mAuthority
                                                                                    validateAuthority:YES
                                                                                      tokenCacheStore:mDefaultTokenCache
                                                                                                error:&error];
    ADAssertNoError;
    XCTAssertNotNil(testContext, "Cannot create the context in setUp.");
    mContext = testContext;
    mProtocolContext = (id<ADAuthenticationContextProtocol>)mContext;
    [testContext->mExpectedRequest1 setObject:OAUTH2_REFRESH_TOKEN forKey:OAUTH2_GRANT_TYPE];
    [testContext->mExpectedRequest1 setObject:mResource forKey:OAUTH2_RESOURCE];
    [testContext->mExpectedRequest1 setObject:mClientId forKey:OAUTH2_CLIENT_ID];
    
    [testContext->mExpectedRequest2 setObject:OAUTH2_REFRESH_TOKEN forKey:OAUTH2_GRANT_TYPE];
    [testContext->mExpectedRequest2 setObject:mResource forKey:OAUTH2_RESOURCE];
    [testContext->mExpectedRequest2 setObject:mClientId forKey:OAUTH2_CLIENT_ID];
    
    //Clear the cache between the tests:
    [mDefaultTokenCache removeAllWithError:&error];
    ADAssertNoError;
}

- (void)tearDown
{
    mContext = nil;//clear, allow deletion between the tests
    mDefaultTokenCache =  nil;

    [self adTestEnd];
    [super tearDown];
}

-(long) cacheCount
{
    XCTAssertNotNil(mDefaultTokenCache);
    ADAuthenticationError* error;
    NSArray* all = [mDefaultTokenCache allItemsWithError:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    return all.count;
}

- (void)testNew
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    XCTAssertThrows([ADAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

-(void)testParameterlessInit
{
    XCTAssertThrows([[ADAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

/* A wrapper around adValidateFactoryForInvalidArgument, passing the test class members*/
-(void) adValidateFactoryForInvalidArgument: (NSString*) argument
                                    error: (ADAuthenticationError*) error
{
    [self adValidateFactoryForInvalidArgument:argument
                             returnedObject:mContext
                                      error:error];
}

/* Pass bad authority argument - nil, empty string, etc. */
-(void) checkInvalidAuthorityHandling: (NSString*) authority
{
    //Authority only:
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority & validate:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:YES error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority and cache store:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil tokenCacheStore:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                           tokenCacheStore:mDefaultTokenCache
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority, validate and cache store:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:NO //Non-default value.
                                                           tokenCacheStore:mDefaultTokenCache
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:NO
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES //Non-default value.
                                                           tokenCacheStore:mDefaultTokenCache
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
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
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    ADAuthenticationError* error;
    NSString* authority = @"https://authority.com/oauth2";
    ADTestTokenCacheStore* testStore = [ADTestTokenCacheStore new];
    XCTAssertNotNil(testStore, "Failed to create a test cache store");
    //Minimal creator:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:mDefaultTokenCache
                                    error:error];
    
    //Authority and validation:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:NO
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:mDefaultTokenCache
                                    error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:mDefaultTokenCache
                                    error:error];

    //Authority and token cache store:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];

    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
    
    //Authority, validate and token cache store:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:NO
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:nil
                                    error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:NO
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:testStore
                                    error:error];

    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];
    
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
}

//Clears state in preparation of asynchronous call
-(void) prepareForAsynchronousCall
{
    //Reset the iVars, as they will be set by the callback
    mResult = nil;
    mError = nil;
    
    if ([mContext isKindOfClass:[ADTestAuthenticationContext class]])
    {
        ADTestAuthenticationContext* testContext = (ADTestAuthenticationContext*)mContext;
        testContext->mNumRequests = 0;//Reset to ensure that the number is verified
    }
}

//Checks the correctness of the authentication result, passed to the callback.
-(void) validateAsynchronousResultWithLine: (int) line
{
    XCTAssertNotNil(mResult, "Result should not be nil.");
    if ([mContext isKindOfClass:[ADTestAuthenticationContext class]])
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
        XCTAssertNil(mResult.accessToken);
    }
    if (mResult && mResult.status == AD_SUCCEEDED)
    {
        XCTAssertNil(mError, "Error should be nil on success. Error: %@", mError.errorDetails);
        XCTAssertNotNil(mResult.accessToken);
        XCTAssertNotNil(mResult.tokenCacheStoreItem.accessToken);
        ADAssertStringEquals(mResult.accessToken, mResult.tokenCacheStoreItem.accessToken);
    }
}

#define acquireTokenAsync [self asynchronousAcquireTokenWithLine:__LINE__]
/* Helper function to fascilitate calling of the asynchronous acquireToken. 
   Uses the ivars of the test class for the arguments.
 */
-(void) asynchronousAcquireTokenWithLine: (int) line
{
    [self prepareForAsynchronousCall];

    static volatile int completion = 0;
    [self adCallAndWaitWithFile:@"" __FILE__ line:line completionSignal: &completion block:^
     {
         ADAuthenticationCallback callback = ^(ADAuthenticationResult* result){
             //Fill in the iVars with the result:
             mResult = result;
             mError = mResult.error;
             ASYNC_BLOCK_COMPLETE(completion);
         };
         if (mSilent)
         {
             [mContext acquireTokenSilentWithResource:mResource
                                             clientId:mClientId
                                          redirectUri:mRedirectURL
                                               userId:mUserId
                                      completionBlock:callback];
         }
         else
         {
             [mContext acquireTokenWithResource:mResource
                                       clientId:mClientId
                                    redirectUri:mRedirectURL
                                 promptBehavior:mPromptBehavior
                                         userId:mUserId
                           extraQueryParameters:nil
                                completionBlock:callback];
         }

     }];
    [self validateAsynchronousResultWithLine:line];
}

//Local override, using class iVars:
-(ADTokenCacheStoreItem*) adCreateCacheItem
{
    ADTokenCacheStoreItem* item = [super adCreateCacheItem];
    item.resource = mResource;
    item.authority = mAuthority;
    item.clientId = mClientId;
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:mUserId error:&error];
    
    return item;
}

-(void) testAcquireTokenBadCompletionBlock
{
    ADAssertThrowsArgument([mContext acquireTokenWithResource:mResource clientId:mClientId redirectUri:mRedirectURL completionBlock:nil]);
}


-(void) testAcquireTokenBadResource
{
    mResource = nil;
    acquireTokenAsync;
    [self adValidateForInvalidArgument:@"resource" error:mError];
    
    mResource = @"   ";
    acquireTokenAsync;
    [self adValidateForInvalidArgument:@"resource" error:mError];
}

-(void) testAcquireTokenBadClientId
{
    mClientId = nil;
    acquireTokenAsync;
    [self adValidateForInvalidArgument:@"clientId" error:mError];
    
    mClientId = @"    ";
    acquireTokenAsync;
    [self adValidateForInvalidArgument:@"clientId" error:mError];
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
    
    [mDefaultTokenCache addOrUpdateItem:item error:&error];
    ADAssertNoError;
}

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
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
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
    mUserId = user1;
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, user1TokenValue);
    
    mUserId = nil;
    //Try the same, but with refresh tokens only:
    [self addCacheWithToken:nil refreshToken:@"refresh1" userId:user1];
    [self addCacheWithToken:nil refreshToken:@"refresh2" userId:user2];
    ADAssertLongEquals(2, [self cacheCount]);
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
    ADAssertLongEquals(2, [self cacheCount]);
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
    
    ADTokenCacheStoreItem* item = [mDefaultTokenCache getItemWithKey:key userId:mUserId error:&error];
    if (error)
    {
        [self recordFailureWithDescription:error.errorDetails inFile:@"" __FILE__ atLine:line expected:NO];
        return nil;
    }
    if (!item)
    {
        [self recordFailureWithDescription:@"Item not present." inFile:@"" __FILE__ atLine:line expected:NO];
        return nil;
    }
    
    [self adAssertStringEquals:item.accessToken stringExpression:@"item.accessToken" expected:accessToken file:__FILE__ line:line];
    [self adAssertStringEquals:item.refreshToken stringExpression:@"item.refreshToken" expected:refreshToken file:__FILE__ line:line];
    return item;
}

-(void) testAcquireTokenSilent
{
    ADAuthenticationError* error;
    mSilent = YES;

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
    NSArray* allItems = [mDefaultTokenCache allItemsWithError:&error];
    ADAssertNoError;
    XCTAssertTrue(allItems.count == 1);
    ADTokenCacheStoreItem* item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    [mDefaultTokenCache addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The access token is expired and the refresh token is nil, so it should fail:
    acquireTokenAsync;
    ADAssertLongEquals(mResult.status, AD_FAILED);
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Now add an item with a fake refresh token:
    XCTAssertTrue([self cacheCount] == 0, "Expired items should be removed from the cache");
    NSString* refreshToken = @"some refresh token";
    [self addCacheWithToken:someTokenValue refreshToken:refreshToken];
    allItems = [mDefaultTokenCache allItemsWithError:&error];
    ADAssertNoError;
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
    XCTAssertTrue([self cacheCount] == 0, "Bad refresh tokens should be removed from the cache");
    
    //Now put a refresh token, but return a broad refresh token:
    [self addCacheWithToken:nil refreshToken:refreshToken];
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_ERROR];//Restore
    NSString* broadRefreshToken = @"broad refresh token testAcquireTokenWithNoPrompt";
    NSString* anotherAccessToken = @"another access token testAcquireTokenWithNoPrompt";
    [self.testContext->mResponse1 setObject:anotherAccessToken forKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:broadRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    //Next line makes it a broad token:
    [self.testContext->mResponse1 setObject:@"anything" forKey:OAUTH2_RESOURCE];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    ADAssertStringEquals(mResult.accessToken, anotherAccessToken);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.refreshToken, broadRefreshToken);
    
    //Put a valid token in the cache, but set context token cache to nil:
    [self addCacheWithToken:someTokenValue refreshToken:@"some refresh token"];
    mContext.tokenCacheStore = nil;
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
}

-(void) testGenericErrors
{
    //Refresh token in the cache, but there is no connection to the server. We should not try to open a credentials web view:
    NSString* refreshToken = @"testGenericErrors refresh token";
    [self addCacheWithToken:nil refreshToken:refreshToken];
    XCTAssertTrue([self cacheCount] == 1);
    int errorCode = 42;
    ADAuthenticationError* error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:NSPOSIXErrorDomain code:errorCode userInfo:nil] errorDetails:@"Bad connection"];
    [self.testContext->mExpectedRequest1 setObject:refreshToken forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mResponse1 setObject:error forKey:AUTH_NON_PROTOCOL_ERROR];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the refresh token cannot be used.");
    ADAssertLongEquals(mResult.error.code, errorCode);
    XCTAssertTrue([self cacheCount] == 1, "Nothing should be removed from the cache.");
    
    //Now simulate restoring of the connection and server error, ensure that attempt was made to prompt for credentials:
    mSilent = YES;
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(mResult.error.code, AD_ERROR_USER_INPUT_NEEDED);
    XCTAssertTrue([self cacheCount] == 0, "Bad refresh token should be removed.");
}

-(void) testBroadRefreshTokenSingleUser
{
    //#1: no access token in the cache, however, broad token exists.
    //Broad token is used, but exact refresh token is returned:
    NSString* broadToken = @"testBroadRefreshToken some broad token";
    NSString* accessToken = @"testBroadRefreshToken some access token";
    NSString* exactRefreshToken = @"testBroadRefreshToken exact refresh token";
    [self addCacheWithToken:nil refreshToken:broadToken userId:mUserId resource:nil];
    XCTAssertTrue([self cacheCount] == 1);
    [self.testContext->mExpectedRequest1 setObject:broadToken forKey:OAUTH2_REFRESH_TOKEN];
    //Add both access and refresh token:
    [self.testContext->mResponse1 setObject:accessToken forKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:@"3500" forKey:@"expires_in"];
    [self.testContext->mResponse1 setObject:exactRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    acquireTokenAsync;
    XCTAssertEqual(mResult.status, AD_SUCCEEDED);
    XCTAssertFalse(mResult.multiResourceRefreshToken);
    //Now verify the cache contents for the new broad refresh token and the access token:
    XCTAssertTrue([self cacheCount] == 2);
    ADTokenCacheStoreItem* exactItem = [self verifyCacheWithResource:mResource accessToken:accessToken refreshToken:exactRefreshToken line:__LINE__];
    NSDate* expiration = exactItem.expiresOn;
    NSDate* minExpiration = [NSDate dateWithTimeIntervalSinceNow:(3500 - 10)];
    ADAssertLongEquals(NSOrderedAscending, [minExpiration compare:expiration]);
    NSDate* maxExpiration = [NSDate dateWithTimeIntervalSinceNow:(3500 + 10)];
    ADAssertLongEquals(NSOrderedDescending, [maxExpiration compare:expiration]);
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
    XCTAssertTrue([self cacheCount] == 2);
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
    XCTAssertTrue(mResult.multiResourceRefreshToken);
    ADAssertLongEquals(3, [self cacheCount]);
    [self verifyCacheWithResource:oldResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
    [self verifyCacheWithResource:nil accessToken:nil refreshToken:broadToken2 line:__LINE__];
    ADTokenCacheStoreItem* newItem = [self verifyCacheWithResource:mResource accessToken:accessToken3 refreshToken:nil line:__LINE__];
    
    //#4: Now try failing from both the exact and the broad refresh token to ensure that this code path
    //works. Both items should be removed from the cache. Also ensures that the credentials ask is attempted in this case.
    self.testContext->mAllowTwoRequests = YES;
    mSilent = YES;
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
    ADAssertLongEquals(1, [self cacheCount]);
    [self verifyCacheWithResource:oldResource accessToken:accessToken2 refreshToken:nil line:__LINE__];
}

-(void) testWrongUser
{
    ADAuthenticationError* error;
    NSString* idToken = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9.";

    NSString* broadToken = @"testWrongUser some broad token";
    NSString* accessToken = @"testWrongUser some access token";
    NSString* exactRefreshToken = @"testWrongUser exact refresh token";
    NSString* requestUser = @"testWrongUser requestUser";
    
    //#1: access token exists in the cache for different user, make sure that the library attempts to use UI
    [self addCacheWithToken:accessToken refreshToken:nil userId:mUserId resource:mResource];
    mUserId = requestUser;
    acquireTokenAsync;
    ADAssertLongEquals(AD_ERROR_NO_MAIN_VIEW_CONTROLLER, mResult.error.code);
    
    //#2: Only exact refresh token
    [mDefaultTokenCache removeAllWithError:&error];
    ADAssertNoError;
    [self addCacheWithToken:nil refreshToken:exactRefreshToken userId:requestUser resource:mResource];
    [self.testContext->mResponse1 setObject:idToken forKey:OAUTH2_ID_TOKEN];
    [self.testContext->mResponse1 setObject:accessToken forKey:OAUTH2_ACCESS_TOKEN];
    acquireTokenAsync;
    ADAssertLongEquals(AD_ERROR_WRONG_USER, mResult.error.code);
    ADAssertLongEquals(2, [self cacheCount]);//The new token should be added to the cache

    //#3: Broad refresh token
    [mDefaultTokenCache removeAllWithError:&error];
    ADAssertNoError;
    [self addCacheWithToken:nil refreshToken:broadToken userId:requestUser resource:nil];
    acquireTokenAsync;
    ADAssertLongEquals(AD_ERROR_WRONG_USER, mResult.error.code);
    ADAssertLongEquals(2, [self cacheCount]);//The new token should be added to the cache
}

-(void) testWrongUserADFS
{
    ADAuthenticationError* error;
    NSString* broadToken = @"testWrongUserADFS some broad token";
    NSString* accessToken = @"testWrongUserADFS some access token";
    NSString* exactRefreshToken = @"testWrongUserADFS exact refresh token";
    NSString* requestUser = @"testWrongUserADFS requestUser";
    
    //#1: access token exists in the cache, no user information available:
    [self addCacheWithToken:accessToken refreshToken:nil userId:nil resource:mResource];
    mUserId = requestUser;
    acquireTokenAsync;
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.accessToken, accessToken);
    
    //#2: Only exact refresh token, again, no user information:
    [mDefaultTokenCache removeAllWithError:&error];
    [self addCacheWithToken:nil refreshToken:exactRefreshToken userId:nil resource:mResource];
    [self.testContext->mResponse1 setObject:accessToken forKey:OAUTH2_ACCESS_TOKEN];
    acquireTokenAsync;
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.accessToken, accessToken);
    
    //#3: Broad refresh token
    [mDefaultTokenCache removeAllWithError:&error];
    [self addCacheWithToken:nil refreshToken:broadToken userId:nil resource:nil];
    acquireTokenAsync;
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.accessToken, accessToken);
}

-(void) testCorrelationIdProperty
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    XCTAssertNil(mContext.correlationId, "default should be nil");
    
    NSUUID* first = [NSUUID UUID];
    mContext.correlationId = first;
    XCTAssertEqual(mContext.correlationId, first);
    
    NSUUID* second = [NSUUID UUID];
    mContext.correlationId = second;
    XCTAssertEqual(mContext.correlationId, second);
    
    mContext.correlationId = nil;
    XCTAssertNil(mContext.correlationId);
}

-(void) testCorrelationIdRefreshToken
{
    [self addCacheWithToken:nil refreshToken:@"some refresh token"];
    
    //First make sure it is passed:
    NSUUID* correlationId = [NSUUID UUID];
    mContext.correlationId = correlationId;
    [self.testContext->mResponse1 setObject:@"accessToken" forKey:OAUTH2_ACCESS_TOKEN];
    NSString* idToken = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9.";
    [self.testContext->mResponse1 setObject:idToken forKey:OAUTH2_ID_TOKEN];
    [self.testContext->mResponse1 setObject:[correlationId UUIDString] forKey:OAUTH2_CORRELATION_ID_RESPONSE];
    acquireTokenAsync;
    ADAssertLongEquals(mResult.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(self.testContext->mCorrelationId1, correlationId);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.userInformation.userId, @"boris@msopentechbv.onmicrosoft.com");
}

-(void) testCorrelationIdBroadToken
{
    NSUUID* correlationId = [NSUUID UUID];
    mContext.correlationId = correlationId;
    
    //Enforce two requests to the server. Make sure that the correlationId is preserved:
    [self addCacheWithToken:nil refreshToken:@"some refresh token"];
    [self addCacheWithToken:nil refreshToken:@"broad token" userId:mUserId resource:nil];
    
    self.testContext->mAllowTwoRequests = YES;
    //Pass different UUID to the first (error) response:
    [self.testContext->mResponse1 setObject:[[NSUUID UUID] UUIDString] forKey:OAUTH2_CORRELATION_ID_RESPONSE];
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    
    //Pass invalid UUID to the second (access token) response:
    [self.testContext->mResponse2 setObject:@"invalid UUID" forKey:OAUTH2_CORRELATION_ID_RESPONSE];
    [self.testContext->mResponse2 setObject:@"accessToken" forKey:OAUTH2_ACCESS_TOKEN];

    acquireTokenAsync;
    
    ADAssertLongEquals(mResult.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(self.testContext->mCorrelationId1, correlationId);
    XCTAssertEqualObjects(self.testContext->mCorrelationId2, correlationId);
    ADAssertLogsContain(TEST_LOG_MESSAGE, @"Bad correlation id");
    ADAssertLogsContain(TEST_LOG_MESSAGE, @"Correlation id mismatch");
    
    //Now do the same, but this time return a valid (but different) correlation id:
    NSUUID* anotherOne = [NSUUID UUID];
    [self addCacheWithToken:nil refreshToken:@"some refresh token"];//Force using of refresh token
    [self.testContext->mResponse2 setObject:[anotherOne UUIDString] forKey:OAUTH2_CORRELATION_ID_RESPONSE];
    acquireTokenAsync;
    
    ADAssertLongEquals(mResult.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(self.testContext->mCorrelationId1, correlationId);
    XCTAssertEqualObjects(self.testContext->mCorrelationId2, correlationId);
    ADAssertLogsContainValue(TEST_LOG_INFO, [anotherOne UUIDString]);
}

//Additional tests for the cases that are not covered by the broader scenario tests.
-(void) testExtractCacheItemWithKeyEdgeCases
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    //Nil key
    XCTAssertNil([mProtocolContext extractCacheItemWithKey:nil userId:nil error:nil]);
    BOOL useAccessToken;
    XCTAssertNil([mProtocolContext findCacheItemWithKey:nil userId:nil useAccessToken:&useAccessToken error:nil]);
    
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    XCTAssertNotNil(key);
    ADAssertNoError;
    
    //Put the item in the cache
    error = nil;
    [self->mDefaultTokenCache addOrUpdateItem:item error:&error];
    ADAssertNoError;
    
    error = nil;
    ADTokenCacheStoreItem* extracted = [mProtocolContext extractCacheItemWithKey:key userId:item.userInformation.userId error:&error];
    ADAssertNoError;
    [self adVerifySameWithItem:item item2:extracted];
    error = nil;
    ADTokenCacheStoreItem* found = [mProtocolContext findCacheItemWithKey:key userId:item.userInformation.userId useAccessToken:&useAccessToken error:&error];
    ADAssertNoError;
    XCTAssertTrue(useAccessToken);
    [self adVerifySameWithItem:item item2:found];
    
    mContext.tokenCacheStore = nil;//Set the authority to not use the cache:
    XCTAssertNil([mProtocolContext extractCacheItemWithKey:nil userId:nil error:nil]);
    XCTAssertNil([mProtocolContext findCacheItemWithKey:key userId:item.userInformation.userId useAccessToken:&useAccessToken error:&error]);
}

-(void) testBadAuthorityWithValidation
{
    mAuthority = @"https://MyFakeAuthority.com/MSOpenTechBV.OnMicrosoft.com";
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:&error];
    XCTAssertNotNil(mContext);
    ADAssertNoError;
    
    acquireTokenAsync;
    XCTAssertNotNil(mResult);
    ADAssertLongEquals(AD_FAILED, mResult.status);
    ADAssertLongEquals(AD_ERROR_AUTHORITY_VALIDATION, mError.code);
}

//Used when the framework needs to display an UI and cannot, raising an error
-(void) validateUIError
{
    XCTAssertNotNil(mContext);
    
    //UI is not available in the test framework, so we indirectly test
    //scenarios when we cannot invoke the web view:
    acquireTokenAsync;
    XCTAssertNotNil(mError);
    ADAssertLongEquals(AD_ERROR_NO_MAIN_VIEW_CONTROLLER, mError.code);
    XCTAssertTrue([mError.errorDetails adContainsString:@"ViewController"]);
}

-(void) testUIError
{
    ADAuthenticationError* error;
    
    //Nothing in the cache, UI is needed:
    [mDefaultTokenCache removeAllWithError:&error];
    ADAssertNoError;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:&error];
    ADAssertNoError;
    [self validateUIError];

    //Cache disabled, should always try to open UI for credentials
    error = nil;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority tokenCacheStore:nil error:&error];
    ADAssertNoError;
    [self validateUIError];

    //Cache item present, but force prompt:
    error = nil;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:&error];
    ADAssertNoError;
    [self addCacheWithToken:@"access" refreshToken:nil];
    mPromptBehavior = AD_PROMPT_ALWAYS;
    [self validateUIError];
}
 
-(void) testBadRefreshToken
{
    //Create a normal authority (not a test one):
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:&error];
    XCTAssertNotNil(mContext);
    ADAssertNoError;
    
    //Exact refresh token:
    [self addCacheWithToken:nil refreshToken:@"invalid refresh token"];
    ADAssertLongEquals(1, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the refresh token and fail.
    ADAssertLongEquals(0, [self cacheCount]);
    
    //Broad refresh token:
    [self addCacheWithToken:nil refreshToken:@"invalid broad refresh token" userId:mUserId resource:nil];
    ADAssertLongEquals(1, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the broad refresh token and fail.
    ADAssertLongEquals(0, [self cacheCount]);
    
    //Both exact and broad refresh token:
    [self addCacheWithToken:nil refreshToken:@"another invalid refresh token"];
    [self addCacheWithToken:nil refreshToken:@"another invalid broad refresh token" userId:mUserId resource:nil];
    ADAssertLongEquals(2, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the broad refresh token and fail.
    ADAssertLongEquals(0, [self cacheCount]);
}

//Creates the context with
-(void) testUnreachableAuthority
{
    //Create a normal authority (not a test one):
    ADAuthenticationError* error;
    mAuthority = @"https://SomeValidURLButNonExistentDomain.com/sometenant.com";
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority validateAuthority:NO error:&error];
    XCTAssertNotNil(mContext);
    ADAssertNoError;
    
    //Exact refresh token:
    [self addCacheWithToken:nil refreshToken:@"invalid refresh token"];
    ADAssertLongEquals(1, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the refresh token and fail with system error.
    ADAssertLongEquals(1, [self cacheCount]);//Should not remove anything from cache, assuming that the server is unreachable
    
    //Ensure only broad token and retry the logic:
    [mDefaultTokenCache removeAllWithError:&error];
    ADAssertNoError;
    [self addCacheWithToken:nil refreshToken:@"invalid broad refresh token" userId:mUserId resource:nil];
    acquireTokenAsync;//Will attempt to use the broad refresh token and fail.
    ADAssertLongEquals(1, [self cacheCount]);//Again, shouldn't remove from cache
}

//Tests the additional overloads. The test doesn't go deep, as eventually all of these
//overloads call the same one, just tests that the entry point.
-(void) testAcquireTokenOverloads
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    [self addCacheWithToken:@"cacheToken" refreshToken:nil];

    static volatile int completion = 0;
    ADAuthenticationCallback innerCallback = ^(ADAuthenticationResult* result)
    {
        //Fill in the iVars with the result:
        mResult = result;
        mError = mResult.error;
        ASYNC_BLOCK_COMPLETE(completion);
    };
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
     {
         [mContext acquireTokenWithResource:mResource
                                   clientId:mClientId
                                redirectUri:mRedirectURL
                            completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
     {
         [mContext acquireTokenWithResource:mResource
                                   clientId:mClientId
                                redirectUri:mRedirectURL
                                     userId:mUserId
                            completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);

    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
     {
         [mContext acquireTokenWithResource:mResource
                                   clientId:mClientId
                                redirectUri:mRedirectURL
                                     userId:mUserId
                       extraQueryParameters:@"extraQueryParams=somevalue"
                            completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
}

//Tests the shorter overload of acquireTokenByRefreshToken
//as the method ultimately calls the other overload, which is also used by acquireToken.
//As such, the test is not very deep.
-(void) testAcquireTokenByRefreshTokenSimple_Negative
{
    //There is no resource for this call:
    [self.testContext->mExpectedRequest1 removeObjectForKey:OAUTH2_RESOURCE];
    //Calls the acquireToken
    static volatile int completion = 0;
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
     {
         [mContext acquireTokenByRefreshToken:@"nonExisting one"
                                     clientId:mClientId
                              completionBlock:^(ADAuthenticationResult *result)
          {
              //Fill in the iVars with the result:
              mResult = result;
              mError = mResult.error;
              ASYNC_BLOCK_COMPLETE(completion);
          }];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_FAILED, mResult.status);
}

//Calls the full overload of acquireTokenByRefresh token and waits for the result.
-(void) asyncAcquireTokenByRefreshToken: (NSString*) refreshToken
{
    [self prepareForAsynchronousCall];
    
    static volatile int completion = 0;
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
     {
         [mContext acquireTokenByRefreshToken:refreshToken
                                     clientId:mClientId
                                     resource:mResource
                              completionBlock:^(ADAuthenticationResult *result)
          {
              //Fill in the iVars with the result:
              mResult = result;
              mError = mResult.error;
              ASYNC_BLOCK_COMPLETE(completion);
          }];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
}

//Most of the refresh token functionality is already tested, here we add only
//the specifics to the public function behavior:
-(void) testAcquireTokenByRefreshToken
{
    //Return access and exact refresh tokens:
    NSString* accessToken1 = @"accessToken1";
    NSString* exactRefreshToken = @"exactRefreshToken";
    NSString* refreshToken = @"some refresh token";
    [self.testContext->mResponse1 setObject:accessToken1 forKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:exactRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    [self.testContext->mExpectedRequest1 setObject:refreshToken forKey:OAUTH2_REFRESH_TOKEN];
    [self asyncAcquireTokenByRefreshToken:refreshToken];
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, accessToken1);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.refreshToken, exactRefreshToken);
    ADAssertLongEquals(0, [self cacheCount]);//This method should not write to the cache

    //Return access and broad refresh tokens:
    NSString* accessToken2 = @"accessToken2";
    NSString* broadRefreshToken = @"broadRefreshToken";
    [self.testContext->mResponse1 setObject:accessToken2 forKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:broadRefreshToken forKey:OAUTH2_REFRESH_TOKEN];
    //Presence of "resource" denotes multi-resource refresh token:
    [self.testContext->mResponse1 setObject:@"someresource" forKey:OAUTH2_RESOURCE];
    [self asyncAcquireTokenByRefreshToken:refreshToken];
    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, accessToken2);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.refreshToken, broadRefreshToken);
    ADAssertLongEquals(0, [self cacheCount]);//This method should not write to the cache
    
    //Put stuff in the cache, make sure it is not used:
    [self adClearLogs];
    [self addCacheWithToken:@"cacheAccessToken" refreshToken:@"cacheExactRefreshToken"];
    [self addCacheWithToken:nil refreshToken:@"broadCacheRefreshToken" userId:mUserId resource:nil];
    ADAssertLogsContain(TEST_LOG_INFO, @" addOrUpdateItem:error:]");//Double check that the logging is in place
    
    [self adClearLogs];
    [self asyncAcquireTokenByRefreshToken:refreshToken];

    ADAssertLongEquals(AD_SUCCEEDED, mResult.status);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.accessToken, accessToken2);
    ADAssertStringEquals(mResult.tokenCacheStoreItem.refreshToken, broadRefreshToken);
    ADAssertLogsDoNotContain(TEST_LOG_INFO, @" addOrUpdateItem:error:]");//Cache should not be touched
    ADAssertLongEquals(2, [self cacheCount]);
    
    //Put the same refresh token in the cache, return an error and ensure again that the cache is not touched:
    //refresh tokens should not be removed:
    [self addCacheWithToken:@"cacheAccessToken" refreshToken:refreshToken];
    [self addCacheWithToken:nil refreshToken:refreshToken userId:mUserId resource:nil];
    [self.testContext->mResponse1 removeObjectForKey:OAUTH2_ACCESS_TOKEN];
    [self.testContext->mResponse1 setObject:@"bad_refresh_token" forKey:OAUTH2_ERROR];
    [self adClearLogs];
    [self asyncAcquireTokenByRefreshToken:refreshToken];
    
    ADAssertLongEquals(AD_FAILED, mResult.status);
    ADAssertLogsDoNotContain(TEST_LOG_INFO, @" addOrUpdateItem:error:]");//Cache should not be touched
    ADAssertLongEquals(2, [self cacheCount]);
}

-(void) testAcquireTokenWithRefreshTokenParameters
{
    //Test some parameters cases:
    //RefreshToken nil:
    [self asyncAcquireTokenByRefreshToken:nil];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    [self adValidateForInvalidArgument:@"refreshToken" error:mResult.error];
    
    //RefreshToken empty
    [self asyncAcquireTokenByRefreshToken:@"   "];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    [self adValidateForInvalidArgument:@"refreshToken" error:mResult.error];
    
    //ClientId nil:
    mClientId = nil;
    [self asyncAcquireTokenByRefreshToken:@"refreshToken"];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    [self adValidateForInvalidArgument:@"clientId" error:mResult.error];
    
    //ClientId empty:
    mClientId = @"     ";
    [self asyncAcquireTokenByRefreshToken:@"refreshToken"];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    [self adValidateForInvalidArgument:@"clientId" error:mResult.error];
}

//Hits a the cloud with either a bad server or a bad refresh token:
-(void) testRefreshingTokenWithServerErrors
{
    //Authority cannot be validated or reached:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:@"https://example.com/common" error:nil];
    XCTAssertNotNil(mContext);

    [self asyncAcquireTokenByRefreshToken:@"doesn't matter"];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    ADAssertLongEquals(AD_ERROR_AUTHORITY_VALIDATION, mResult.error.code);
    
    mContext.validateAuthority = NO;
    [self asyncAcquireTokenByRefreshToken:@"doesn't matter"];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    ADAssertStringEquals(mResult.error.domain, NSURLErrorDomain);
    
    //Valid authority, but invalid refresh token:
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:nil];
    XCTAssertNotNil(mContext);
    
    [self asyncAcquireTokenByRefreshToken:@"invalid_refresh_token"];
    ADAssertLongEquals(AD_FAILED, mResult.status);
    ADAssertLongEquals(AD_ERROR_INVALID_REFRESH_TOKEN, mResult.error.code);
    ADAssertStringEquals(mResult.error.protocolCode, @"invalid_grant");
    XCTAssertTrue([mResult.error.errorDetails.lowercaseString adContainsString:@"refresh token"]);
}

@end

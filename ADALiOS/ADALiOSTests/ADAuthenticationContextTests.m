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
#import "../ADALiOS/ADAL.h"
#import "../ADALiOS/ADAuthenticationContext+Internal.h"
#import "ADTestTokenCacheStore.h"
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>
#import "ADWebRequest.h"
#import "ADTestAuthenticationContext.h"
#import "ADTestUtils.h"
#import "../ADALiOS/ADOAuth2Constants.h"
#import "../ADALiOS/ADAuthenticationSettings.h"
#import "../ADALiOS/ADKeychainTokenCacheStore.h"
#import "../ADALiOS/NSArray+ADExtensions.h"
#import "../ADALiOS/NSSet+ADExtensions.h"

const int sAsyncContextTimeout = 10;
@interface ADAuthenticationContextTests : XCTestCase
{
@private
    //The source:
    ADAuthenticationContext* _context;
    ADTestAuthenticationContext* _testContext;
    NSString* _authority;
    NSArray* _scopes;
    NSArray* _additionalScopes;
    NSString* _clientId;
    NSURL* _redirectURL;
    NSString* _userId;
    NSString* _policy;
    ADPromptBehavior _promptBehavior;
    NSString* _assertion;
    ADAssertionType _assertionType;
    
    BOOL _silent;
    
    NSUUID* _correlationId;
    
    //The results:
    ADAuthenticationError* _error;//The error filled by the result;
    ADAuthenticationResult* _result;//Result of asynchronous operation;
}

@end

static ADKeychainTokenCacheStore* s_testCacheStore = nil;


@implementation ADAuthenticationContextTests

- (void)setUp
{
    [super setUp];
    [ADLogger setLevel:ADAL_LOG_LEVEL_INFO];
    if (!s_testCacheStore)
    {
        s_testCacheStore = [[ADKeychainTokenCacheStore alloc] init];
        [s_testCacheStore setServiceKey:@"MSOpenTech.ADAL.Test"];
    }
    
    _authority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    [[ADAuthenticationSettings sharedInstance] setDefaultTokenCacheStore:s_testCacheStore];
    [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
    
    _redirectURL = [NSURL URLWithString:@"http://todolistclient/"];
    _clientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";
    _userId = @"boris@msopentechbv.onmicrosoft.com";
    _promptBehavior = AD_PROMPT_AUTO;
    _silent = NO;
    
    _scopes = @[ @"plantetarydefense.fire", @"planetarydefense.target" ];
    _additionalScopes = nil;
    
    ADAuthenticationError* error;
    ADTestAuthenticationContext* testContext = [[ADTestAuthenticationContext alloc] initWithAuthority:_authority
                                                                                    validateAuthority:YES
                                                                                      tokenCacheStore:s_testCacheStore
                                                                                                error:&error];
    ADAssertNoError;
    XCTAssertNotNil(testContext, "Cannot create the context in setUp.");
    _context = testContext;
    _testContext = testContext;
    
    //Clear the cache between the tests:
    [s_testCacheStore removeAll:&error];
    
    ADAssertNoError;
    [ADAuthenticationSettings sharedInstance].requestTimeOut = 5;
}

- (void)tearDown
{
    _context = nil;//clear, allow deletion between the tests
    [s_testCacheStore removeAll:nil];

    [super tearDown];
}

- (NSString*)encodedStringWithScopes
{
    return [_scopes adUrlFormEncode];
}

- (long)cacheCount
{
    ADAuthenticationError* error;
    NSArray* all = [s_testCacheStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    return all.count;
}

- (void)testNew
{
    XCTAssertThrows([ADAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit
{
    XCTAssertThrows([[ADAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

/* A wrapper around adValidateFactoryForInvalidArgument, passing the test class members*/
- (void)adValidateFactoryForInvalidArgument:(NSString*)argument
                                      error:(ADAuthenticationError*)error
{
    [self adValidateFactoryForInvalidArgument:argument
                             returnedObject:_context
                                      error:error];
}

/* Pass bad authority argument - nil, empty string, etc. */
- (void)checkInvalidAuthorityHandling:(NSString*)authority
{
    //Authority only:
    ADAuthenticationError* error;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority & validate:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:YES error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority and cache store:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil tokenCacheStore:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                           tokenCacheStore:s_testCacheStore
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    //Authority, validate and cache store:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:NO //Non-default value.
                                                           tokenCacheStore:s_testCacheStore
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:NO
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES //Non-default value.
                                                           tokenCacheStore:s_testCacheStore
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:nil
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority" error:error];
}

/* Tests all of the static creators by passing authority as nil. Appropriate error should be returned in all cases. */
- (void)testInitAuthorityNil
{
    [self checkInvalidAuthorityHandling:nil];
}

- (void)testInitAuthorityEmpty
{
    [self checkInvalidAuthorityHandling:@""];
}

- (void)testInitAuthorityBlank
{
    [self checkInvalidAuthorityHandling:@"      "];
}

- (void)checkContextObjectWithAuthority:(NSString*)authority
                               validate:(BOOL)validate
                        tokenCacheStore:(id<ADTokenCacheStoring>)tokenCacheStore
                                  error:(ADAuthenticationError*)error;
{
    XCTAssertNil(error, "No error should be raised here. Error: %@", error.errorDetails);
    XCTAssertNotNil(_context, "Context should be valid in this case.");
    XCTAssertEqualObjects(authority, _context.authority);
    XCTAssertEqual(validate, _context.validateAuthority, "Unexpected validate authority value.");
    XCTAssertEqualObjects(tokenCacheStore, _context.tokenCacheStore, "Unexpected token cache store.");
}

- (void)testProperties
{
    ADAuthenticationError* error;
    NSString* authority = @"https://authority.com/oauth2";
    ADTestTokenCacheStore* testStore = [ADTestTokenCacheStore new];
    XCTAssertNotNil(testStore, "Failed to create a test cache store");
    //Minimal creator:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:s_testCacheStore
                                    error:error];
    
    //Authority and validation:
    _context = [ADTestAuthenticationContext authenticationContextWithAuthority:authority
                                                             validateAuthority:NO
                                                                         error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:s_testCacheStore
                                    error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:s_testCacheStore
                                    error:error];

    //Authority and token cache store:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];

    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
    
    //Authority, validate and token cache store:
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:NO
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:nil
                                    error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:NO
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:NO
                          tokenCacheStore:testStore
                                    error:error];

    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                           tokenCacheStore:nil
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:nil
                                    error:error];
    
    _context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                         validateAuthority:YES
                                                           tokenCacheStore:testStore
                                                                     error:&error];
    [self checkContextObjectWithAuthority:authority
                                 validate:YES
                          tokenCacheStore:testStore
                                    error:error];
}

//Clears state in preparation of asynchronous call
- (void)prepareForAsynchronousCall
{
    //Reset the iVars, as they will be set by the callback
    _result = nil;
    _error = nil;
}

//Checks the correctness of the authentication result, passed to the callback.
- (void)validateAsynchronousResultWithLine:(int)line
{
    XCTAssertNotNil(_result, "Result should not be nil.");
    if ([_context isKindOfClass:[ADTestAuthenticationContext class]])
    {
        //Handle errors with the expected server communication:
        ADTestAuthenticationContext* testContext = (ADTestAuthenticationContext*)_context;
        if ([testContext errorMessage])
        {
            [self recordFailureWithDescription:[testContext errorMessage] inFile:@"" __FILE__ atLine:line expected:NO];
            return;
        }
    }
    if (_result && _result.status != AD_SUCCEEDED)
    {
        XCTAssertNotNil(_error, "Error should be returned if the result did not succeed.");
        //These will be used by the tests to denote success, so we want to make sure that they are not
        //set in case of failure:
        XCTAssertNil(_result.tokenCacheStoreItem.accessToken);
        XCTAssertNil(_result.tokenCacheStoreItem.refreshToken);
        XCTAssertNil(_result.accessToken);
    }
    if (_result && _result.status == AD_SUCCEEDED)
    {
        XCTAssertNil(_error, "Error should be nil on success. Error: %@", _error.errorDetails);
        XCTAssertNotNil(_result.accessToken);
        XCTAssertNotNil(_result.tokenCacheStoreItem.accessToken);
        XCTAssertEqualObjects(_result.accessToken, _result.tokenCacheStoreItem.accessToken);
    }
}


#define acquireTokenForAssertionAsync [self asynchronousAcquireTokenForAssertionWithLine:__LINE__]
- (void)asynchronousAcquireTokenForAssertionWithLine:(int)line
{
    [self prepareForAsynchronousCall];
    
    __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self adCallAndWaitWithFile:@"" __FILE__ line:line semaphore:sem block:^
     {
         [_context acquireTokenForAssertion:_assertion
                              assertionType:_assertionType
                                     scopes:_scopes
                           additionalScopes:nil
                                   clientId:_clientId
                                 identifier:[ADUserIdentifier identifierWithId:_userId type:RequiredDisplayableId]
                            completionBlock:^(ADAuthenticationResult *result)
          {
              //Fill in the iVars with the result:
              self->_result = result;
              self->_error = _result.error;
              dispatch_semaphore_signal(sem);
          }];
     }];
    [self validateAsynchronousResultWithLine:line];
}

#define acquireTokenAsync [self asynchronousAcquireTokenWithLine:__LINE__]
/* Helper function to fascilitate calling of the asynchronous acquireToken. 
   Uses the ivars of the test class for the arguments.
 */
- (void)asynchronousAcquireTokenWithLine:(int)line
{
    [self prepareForAsynchronousCall];
    __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self adCallAndWaitWithFile:@"" __FILE__ line:line semaphore:sem block:^
     {
         ADAuthenticationCallback callback = ^(ADAuthenticationResult* result){
             //Fill in the iVars with the result:
             _result = result;
             _error = _result.error;
             dispatch_semaphore_signal(sem);
         };
         if (_silent)
         {
             [_context acquireTokenSilentWithScopes:_scopes
                                          clientId:_clientId
                                       redirectUri:_redirectURL
                                       identifier:[ADUserIdentifier identifierWithId:_userId type:RequiredDisplayableId]
                                   completionBlock:callback];
         }
         else
         {
             [_context acquireTokenWithScopes:_scopes
                            additionalScopes:nil
                                       clientId:_clientId
                                    redirectUri:_redirectURL
                                  identifier:[ADUserIdentifier identifierWithId:_userId type:RequiredDisplayableId]
                               promptBehavior:AD_PROMPT_AUTO
                           extraQueryParameters:nil
                                completionBlock:callback];
         }

     }];
    [self validateAsynchronousResultWithLine:line];
}

//Local override, using class iVars:
- (ADTokenCacheStoreItem*)adCreateCacheItem
{
    ADTestUtils* testUtils = [[ADTestUtils alloc] init];
    [testUtils setAuthority:_authority];
    [testUtils setClientId:_clientId];
    [testUtils setUsername:_userId];
    [testUtils setScopes:_scopes];
    
    NSString* errorDetails = nil;
    return [testUtils createCacheItem:&errorDetails];
}

- (void)testAcquireTokenBadCompletionBlock
{
    ADAssertThrowsArgument([_context acquireTokenWithScopes:_scopes
                                           additionalScopes:nil
                                                   clientId:_clientId
                                                redirectUri:_redirectURL
                                             promptBehavior:AD_PROMPT_AUTO
                                            completionBlock:nil]);
}

- (void)testAcquireTokenBadScopes
{
    _scopes = nil;
    acquireTokenAsync;
    ADAssertArgumentError(@"scopes", _error);
    _scopes = @[];
    acquireTokenAsync;
    ADAssertArgumentError(@"scopes", _error);
    
    _scopes = @[@"", @"    "];
    acquireTokenAsync;
    ADAssertArgumentError(@"scopes", _error);
}

- (void)testAcquireTokenBadClientId
{
    _clientId = nil;
    acquireTokenAsync;
    ADAssertArgumentError(@"clientId", _error);
    
    _clientId = @"    ";
    acquireTokenAsync;
    ADAssertArgumentError(@"clientId", _error);
}

- (void)addCacheWithToken:(NSString*)accessToken
             refreshToken:(NSString*)refreshToken
                   userId:(NSString*)userId
                   scopes:(NSSet*)scopes
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.scopes = scopes;
    item.accessToken = accessToken;
    item.refreshToken = refreshToken;
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    item.authority = _authority;
    item.clientId = _clientId;
    item.profileInfo = [ADProfileInfo profileInfoWithUsername:userId error:nil];
    [_testContext.tokenCacheStore addOrUpdateItem:item error:nil];
}

- (void)addCacheWithToken:(NSString*)accessToken
             refreshToken:(NSString*)refreshToken
                   userId:(NSString*)userId
{
    [self addCacheWithToken:accessToken
               refreshToken:refreshToken
                     userId:userId
                     scopes:[NSSet setWithArray:_scopes]];
}

- (NSArray*)scopesWithAddedByLibrary
{
    return [_scopes arrayByAddingObjectsFromArray:@[@"offline_access", @"openid"]];
}

- (void)addCacheWithToken:(NSString*)accessToken
             refreshToken:(NSString*)refreshToken
{
    [self addCacheWithToken:accessToken
               refreshToken:refreshToken
                     userId:_userId
                     scopes:[NSSet setWithArray:[self scopesWithAddedByLibrary]]];
}

- (NSDictionary*)defaultRequest
{
    return @{ OAUTH2_GRANT_TYPE : OAUTH2_REFRESH_TOKEN,
              OAUTH2_CLIENT_ID : _clientId,
              OAUTH2_SCOPE : [[self scopesWithAddedByLibrary] adSpaceDeliminatedString] };
}

- (NSDictionary*)requestWithOverrides:(id)obj, ... __attribute__((sentinel))
{
    NSMutableDictionary* request = [NSMutableDictionary dictionaryWithDictionary:[self defaultRequest]];
    
    va_list args;
    va_start(args, obj);
    id key = nil;
    id value = nil;
    
    do
    {
        key = va_arg(args, id);
        if (key == nil)
        {
            break;
        }
        
        value = va_arg(args, id);
        if (value == nil)
        {
            break;
        }
        
        [request setObject:value forKey:key];
    } while (1);
    va_end(args);
    
    return request;
}

- (NSDictionary*)defaultResponse
{
    return @{ };
}

- (void)enqueueDefaultRequestResponse
{
    [_testContext queueExpectedRequest:[self defaultRequest]
                              response:[self defaultResponse]];
}

- (void)testAcquireTokenFromAssertion
{
    ADAuthenticationError* error = nil;
    //Nothing in the cache, as we cannot prompt for credentials, this should fail:
    acquireTokenForAssertionAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_INVALID_ARGUMENT);
    
    _assertion = @"some assertion";
    NSString* someTokenValue = @"someToken value";
    
    // Add a token to the cache. It should return the token from the cache and not go out to the network.
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    
    acquireTokenForAssertionAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    
    //Expire the cache item:
    [s_testCacheStore removeAll:&error];
    ADAssertNoError;
    NSArray* allItems = [s_testCacheStore allItems:&error];
    XCTAssertTrue(allItems.count == 0);
    
    NSString* refreshToken = @"refresh token testAcquireTokenWithNoPrompt";
    NSString* anotherAccessToken = @"another access token testAcquireTokenWithNoPrompt";
    
    NSMutableDictionary* request = [NSMutableDictionary dictionaryWithDictionary:[self defaultRequest]];
    
    // Override the grant type to make it an assertion request
    [request setObject:OAUTH2_SAML11_BEARER_VALUE forKey:OAUTH2_GRANT_TYPE];
    [request setObject:_assertion forKey:OAUTH2_ASSERTION];
    
    NSDictionary* response = @{ OAUTH2_ACCESS_TOKEN : anotherAccessToken,
                                OAUTH2_REFRESH_TOKEN : refreshToken,
                                OAUTH2_SCOPE : [_scopes adSpaceDeliminatedString] };
    
    [_testContext queueExpectedRequest:request response:response];
    
    acquireTokenForAssertionAsync;
    XCTAssertEqual(_result.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(_result.accessToken, anotherAccessToken);
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.refreshToken, refreshToken);
}


-(void) testAcquireTokenCorrelationId
{
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    NSUUID* corrId = [_context getCorrelationId];
    
    NSMutableDictionary* request = [NSMutableDictionary dictionaryWithDictionary:[self defaultRequest]];
    [request setObject:@"true" forKey:OAUTH2_CORRELATION_ID_REQUEST];
    [request setObject:[corrId UUIDString] forKey:OAUTH2_CORRELATION_ID_REQUEST_VALUE];
    
    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user value";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    XCTAssertNotEqual([corrId UUIDString], [[_context getCorrelationId] UUIDString]);
    corrId = [NSUUID UUID];
    [_context setCorrelationId:corrId];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    XCTAssertEqualObjects([corrId UUIDString], [[_context getCorrelationId] UUIDString]);
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    XCTAssertEqualObjects([corrId UUIDString], [[_context getCorrelationId] UUIDString]);
}

-(void) testAcquireTokenWithUserCache
{
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);

    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user value";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    
    //Cache a token for another user:
    NSString* anotherUserTokenValue = @"another user token value";
    [self addCacheWithToken:anotherUserTokenValue refreshToken:nil userId:@"another user"];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
}

//Tests the scenario where we have a cached item with nil user:
-(void) testAcquireTokenWithNilUserCache
{
    _userId = nil;//Do not pass a user to acquireToken in this test.
    
    //Cache a token for nil user:
    NSString* nilUserTokenValue = @"nil user token";
    [self addCacheWithToken:nilUserTokenValue refreshToken:nil userId:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, nilUserTokenValue);
    
    //Adds a cache for a real user:
    NSString* someUserTokenValue = @"Some user token";
    [self addCacheWithToken:someUserTokenValue refreshToken:nil userId:@"some user"];
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_MULTIPLE_USERS);
}

//Tests the scenario where more than one users exist in the cache:
- (void)testAcquireTokenWithMultiUserCache
{
    _userId = nil;//Do not pass a user to acquireToken in this test.
    
    NSString* user1 = @"user1";
    NSString* user2 = @"user2";
    NSString* user1TokenValue = @"user1 token";
    [self addCacheWithToken:user1TokenValue refreshToken:nil userId:user1];
    NSString* user2TokenValue = @"user2 token";
    [self addCacheWithToken:user2TokenValue refreshToken:nil userId:user2];
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_MULTIPLE_USERS);

    _userId = user1;
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, user1TokenValue);
    
    _userId = nil;
    //Try the same, but with refresh tokens only:
    [self addCacheWithToken:nil refreshToken:@"refresh1" userId:user1];
    [self addCacheWithToken:nil refreshToken:@"refresh2" userId:user2];
    ADAssertLongEquals(2, [self cacheCount]);
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_MULTIPLE_USERS);
}

- (ADTokenCacheStoreItem*)getItemWithScopes:(NSArray*)scopes
                                      error:(ADAuthenticationError* __autoreleasing *)error
{
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:_authority
                                                              clientId:_clientId
                                                                userId:_userId
                                                              uniqueId:nil
                                                                idType:RequiredDisplayableId
                                                                policy:_policy
                                                                scopes:[NSSet setWithArray:scopes]
                                                                 error:error];
    if (!key)
    {
        return nil;
    }
    
    ADTokenCacheStoreItem* item = [s_testCacheStore getItemWithKey:key error:error];
    NSSet* setScopes = [NSSet setWithArray:scopes];
    if (![setScopes isSubsetOfSet:[item scopes]])
    {
        return nil;
    }
    
    return item;
}

#define VERIFY_CACHE_FOR_SCOPES(_SCOPES, _ACCESS_TOKEN, _REFRESH_TOKEN) { \
    ADAuthenticationError* _ERROR = nil; \
    ADTokenCacheStoreItem* _ITEM = [self getItemWithScopes:_SCOPES error:&_ERROR]; \
    XCTAssertNotNil(_ITEM, @"failed to retrieve item: %@", _ERROR.errorDetails); \
    if (_ITEM) { \
        XCTAssertEqualObjects(_ACCESS_TOKEN, _ITEM.accessToken, @"accessTokens do not match, expected (%@) actual (%@)", _ACCESS_TOKEN, _ITEM.accessToken); \
        XCTAssertEqualObjects(_REFRESH_TOKEN, _ITEM.refreshToken, @"refreshTokens do not match, expected (%@) actual (%@)", _REFRESH_TOKEN, _ITEM.refreshToken); \
    } \
}

- (void)testAcquireTokenSilent
{
    ADAuthenticationError* error = nil;
    _silent = YES;

    //Nothing in the cache, as we cannot prompt for credentials, this should fail:
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Something in the cache, should work even with AD_PROMPT_NEVER:
    NSString* someTokenValue = @"someToken value";
    [self addCacheWithToken:someTokenValue refreshToken:nil];
    acquireTokenAsync;
    XCTAssertEqualObjects(_result.tokenCacheStoreItem.accessToken, someTokenValue);
    
    //Expire the cache item:
    NSArray* allItems = [s_testCacheStore allItems:&error];
    ADAssertNoError;
    XCTAssertTrue(allItems.count == 1);
    ADTokenCacheStoreItem* item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    [s_testCacheStore addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The access token is expired and the refresh token is nil, so it should fail:
    acquireTokenAsync;
    ADAssertLongEquals(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_USER_INPUT_NEEDED);
    
    //Now add an item with a fake refresh token:
    XCTAssertTrue([self cacheCount] == 0, "Expired items should be removed from the cache");
    NSString* refreshToken = @"some refresh token";
    [self addCacheWithToken:someTokenValue refreshToken:refreshToken];
    allItems = [s_testCacheStore allItems:&error];
    ADAssertNoError;
    XCTAssertTrue(allItems.count == 1);
    item = [allItems objectAtIndex:0];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];//Expire it.
    [s_testCacheStore addOrUpdateItem:item error:&error];//Udpate the cache.
    ADAssertNoError;
    //The server error should result in removal of the refresh token from the cache:
    
    NSDictionary* response = @{ OAUTH2_ERROR : @"bad_refresh_token" };
    NSDictionary* request = [self requestWithOverrides:OAUTH2_REFRESH_TOKEN, refreshToken, nil];
    [_testContext queueExpectedRequest:request response:response];
    
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED);
    ADAssertLongEquals(_result.error.code, AD_ERROR_USER_INPUT_NEEDED);
    XCTAssertTrue([self cacheCount] == 0, "Bad refresh tokens should be removed from the cache");
    
    //Put a valid token in the cache, but set context token cache to nil:
    [self addCacheWithToken:someTokenValue refreshToken:@"some refresh token"];
    _context.tokenCacheStore = nil;
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(_result.error.code, AD_ERROR_USER_INPUT_NEEDED);
}

- (void)testGenericErrors
{
    //Refresh token in the cache, but there is no connection to the server. We should not try to open a credentials web view:
    NSString* refreshToken = @"testGenericErrors refresh token";
    [self addCacheWithToken:nil refreshToken:refreshToken];
    XCTAssertTrue([self cacheCount] == 1);
    int errorCode = 42;
    ADAuthenticationError* error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:NSPOSIXErrorDomain code:errorCode userInfo:nil] errorDetails:@"Bad connection"];
    
    NSDictionary* request = [self requestWithOverrides:OAUTH2_REFRESH_TOKEN, refreshToken, nil];
    NSDictionary* response = @{ AUTH_NON_PROTOCOL_ERROR : error };
    [_testContext queueExpectedRequest:request response:response];
    
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED, "AcquireToken should fail, as the refresh token cannot be used.");
    ADAssertLongEquals(_result.error.code, errorCode);
    XCTAssertTrue([self cacheCount] == 1, "Nothing should be removed from the cache.");
    
    //Now simulate restoring of the connection and server error, ensure that attempt was made to prompt for credentials:
    _silent = YES;
    
    response = @{ OAUTH2_ERROR : @"bad_refresh_token" };
    [_testContext queueExpectedRequest:request response:response];
    acquireTokenAsync;
    XCTAssertEqual(_result.status, AD_FAILED, "AcquireToken should fail, as the credentials are needed without cache.");
    ADAssertLongEquals(_result.error.code, AD_ERROR_USER_INPUT_NEEDED);
    XCTAssertTrue([self cacheCount] == 0, "Bad refresh token should be removed.");
}

- (void)testWrongUser
{
    ADAuthenticationError* error;
    NSString* profileInfo = [[ADTestUtils defaultUtils] rawProfileInfo];

    NSString* accessToken = @"testWrongUser some access token";
    NSString* exactRefreshToken = @"testWrongUser exact refresh token";
    NSString* requestUser = @"testWrongUser requestUser";
    NSDictionary* response = nil;
    
    NSArray* cachedScopes = @[@"planetarydefense.target"];
    
    //#1: access token exists in the cache for different user, make sure that the library attempts to use UI
    [self addCacheWithToken:accessToken refreshToken:exactRefreshToken userId:_userId scopes:[NSSet setWithArray:cachedScopes]];
    _scopes = cachedScopes;
    _userId = requestUser;
    acquireTokenAsync;
    ADAssertLongEquals(AD_ERROR_NO_MAIN_VIEW_CONTROLLER, _result.error.code);
    
    [s_testCacheStore removeAll:&error];
    ADAssertNoError;
    
    // Add into cache a token with just the targetting scope
    [self addCacheWithToken:accessToken refreshToken:exactRefreshToken userId:requestUser scopes:[NSSet setWithArray:cachedScopes]];
    
    // Now request both target and fire, this should cause a scope mismatch and trigger a request using the RT.
    _scopes = @[@"planetarydefense.target", @"planetarydefense.fire"];
    response = @{ OAUTH2_PROFILE_INFO : profileInfo,
                  OAUTH2_ACCESS_TOKEN : accessToken,
                  OAUTH2_SCOPE : [_scopes adSpaceDeliminatedString]};
    [_testContext queueExpectedRequest:[self defaultRequest] response:response];
    acquireTokenAsync;
    
    // Testing note: If you're seeing this return back 17 (AD_ERROR_NO_MAIN_VIEW_CONTROLLER) instead of 19, that usually means that
    // the cache did not match, it didn't find a refresh token, and went on to try to get a code.
    ADAssertLongEquals(AD_ERROR_WRONG_USER, _result.error.code);
    ADAssertLongEquals(2, [self cacheCount]); // The new user gets cached as well
}

//Additional tests for the cases that are not covered by the broader scenario tests.
- (void)testExtractCacheItemWithKeyEdgeCases
{
    //Nil key
    XCTAssertNil([_context extractCacheItemWithKey:nil
                                            userId:nil
                                             error:nil]);
    BOOL useAccessToken;
    XCTAssertNil([_context findCacheItemWithKey:nil
                                         userId:nil
                                 useAccessToken:&useAccessToken
                                          error:nil]);
    
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    ADUserIdentifier* userId = [ADUserIdentifier identifierWithId:item.profileInfo.username];
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    XCTAssertNotNil(key);
    ADAssertNoError;
    
    //Put the item in the cache
    error = nil;
    [s_testCacheStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    
    error = nil;
    ADTokenCacheStoreItem* extracted = [_context extractCacheItemWithKey:key
                                                                  userId:userId
                                                                   error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item, extracted);
    error = nil;
    ADTokenCacheStoreItem* found = [_context findCacheItemWithKey:key
                                                           userId:userId
                                                   useAccessToken:&useAccessToken
                                                            error:&error];
    ADAssertNoError;
    XCTAssertTrue(useAccessToken);
    XCTAssertEqualObjects(item, found);
    
    _context.tokenCacheStore = nil;//Set the authority to not use the cache:
    XCTAssertNil([_context extractCacheItemWithKey:nil
                                            userId:nil
                                             error:nil]);
    XCTAssertNil([_context findCacheItemWithKey:key
                                         userId:userId
                                 useAccessToken:&useAccessToken
                                          error:&error]);
}

-(void) testBadAuthorityWithValidation
{
    _authority = @"https://MyFakeAuthority.microsoft.com/MSOpenTechBV.OnMicrosoft.com";
    ADAuthenticationError* error;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority error:&error];
    XCTAssertNotNil(_context);
    ADAssertNoError;
    
    acquireTokenAsync;
    XCTAssertNotNil(_result);
    ADAssertLongEquals(AD_FAILED, _result.status);
    ADAssertLongEquals(AD_ERROR_AUTHORITY_VALIDATION, _error.code);
}

// Used when the framework needs to display an UI and cannot, raising an error
// UI is not available in the test framework, so we indirectly test
// scenarios when we cannot invoke the web view:
#define VALIDATE_UI_ERROR { \
    XCTAssertNotNil(_context); \
    acquireTokenAsync; \
    XCTAssertNotNil(_error); \
    ADAssertLongEquals(AD_ERROR_NO_MAIN_VIEW_CONTROLLER, _error.code); \
    XCTAssertTrue([_error.errorDetails adContainsString:@"ViewController"]); \
}

- (void)testUIError
{
    ADAuthenticationError* error;
    
    //Nothing in the cache, UI is needed:
    [s_testCacheStore removeAll:&error];
    ADAssertNoError;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority error:&error];
    ADAssertNoError;
    VALIDATE_UI_ERROR;

    //Cache disabled, should always try to open UI for credentials
    error = nil;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority tokenCacheStore:nil error:&error];
    ADAssertNoError;
    VALIDATE_UI_ERROR;

    //Cache item present, but force prompt:
    error = nil;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority error:&error];
    ADAssertNoError;
    [self addCacheWithToken:@"access" refreshToken:nil];
    _promptBehavior = AD_PROMPT_ALWAYS;
    VALIDATE_UI_ERROR;
}
 
- (void)testBadRefreshToken
{
    //Create a normal authority (not a test one):
    ADAuthenticationError* error;
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority error:&error];
    XCTAssertNotNil(_context);
    ADAssertNoError;
    
    //Exact refresh token:
    [self addCacheWithToken:nil refreshToken:@"invalid refresh token"];
    ADAssertLongEquals(1, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the refresh token and fail.
    ADAssertLongEquals(0, [self cacheCount]);
}

//Creates the context with
- (void)testUnreachableAuthority
{
    //Create a normal authority (not a test one):
    ADAuthenticationError* error;
    _authority = @"https://SomeValidURLButNonExistentDomain.com/sometenant.com";
    _context = [ADAuthenticationContext authenticationContextWithAuthority:_authority validateAuthority:NO error:&error];
    XCTAssertNotNil(_context);
    ADAssertNoError;
    
    //Exact refresh token:
    [self addCacheWithToken:nil refreshToken:@"invalid refresh token"];
    ADAssertLongEquals(1, [self cacheCount]);
    
    acquireTokenAsync;//Will attempt to use the refresh token and fail with system error.
    ADAssertLongEquals(1, [self cacheCount]);//Should not remove anything from cache, assuming that the server is unreachable
    
    //Ensure only broad token and retry the logic:
    [s_testCacheStore removeAll:&error];
    ADAssertNoError;
    [self addCacheWithToken:nil refreshToken:@"invalid broad refresh token" userId:_userId scopes:nil];
    acquireTokenAsync;//Will attempt to use the broad refresh token and fail.
    ADAssertLongEquals(1, [self cacheCount]);//Again, shouldn't remove from cache
}

//Tests the additional overloads. The test doesn't go deep, as eventually all of these
//overloads call the same one, just tests that the entry point.
-(void) testAcquireTokenOverloads
{
    [self addCacheWithToken:@"cacheToken" refreshToken:nil];

    __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    ADAuthenticationCallback innerCallback = ^(ADAuthenticationResult* result)
    {
        //Fill in the iVars with the result:
        _result = result;
        _error = _result.error;
        dispatch_semaphore_signal(sem);
    };

    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ semaphore:sem block:^
     {
         [_context acquireTokenWithScopes:_scopes
                         additionalScopes:nil
                                 clientId:_clientId
                              redirectUri:_redirectURL
                           promptBehavior:AD_PROMPT_AUTO
                          completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, _result.status);
    
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ semaphore:sem block:^
     {
         [_context acquireTokenWithScopes:_scopes
                         additionalScopes:nil
                                 clientId:_clientId
                              redirectUri:_redirectURL
                               identifier:_userId ? [ADUserIdentifier identifierWithId:_userId type:RequiredDisplayableId] : nil
                           promptBehavior:AD_PROMPT_AUTO
                          completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, _result.status);

    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ semaphore:sem block:^
     {
         [_context acquireTokenWithScopes:_scopes
                         additionalScopes:nil
                                 clientId:_clientId
                              redirectUri:_redirectURL
                               identifier:_userId ? [ADUserIdentifier identifierWithId:_userId type:RequiredDisplayableId] : nil
                           promptBehavior:AD_PROMPT_AUTO
                     extraQueryParameters:@"extraQueryParams=somevalue"
                          completionBlock:innerCallback];
     }];
    [self validateAsynchronousResultWithLine:__LINE__];
    ADAssertLongEquals(AD_SUCCEEDED, _result.status);
}

@end

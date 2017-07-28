// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <XCTest/XCTest.h>

#import "ADTestLoader.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"

static NSString *GetReason(NSError *error)
{
    NSException *exception = error.userInfo[@"exception"];
    if (![exception isKindOfClass:[NSException class]])
    {
        return nil;
    }
    return exception.reason;
}

@interface ADTestLoaderCacheTests : XCTestCase

@end

@implementation ADTestLoaderCacheTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}


- (void)testCache_whenEmpty
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 0);
}

- (void)testCache_unsupportedElementType_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><MonsterToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

#pragma mark -
#pragma mark AccessToken Element Tests

- (void)testAccessToken_withMinimumAttributes_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
}


- (void)testAccessToken_withNoAttributes_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

#pragma mark -
#pragma mark RefreshToken Element Tests

- (void)testRefreshToken_withMinimumAttributes_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
}


- (void)testRefreshToken_withNoAttributes_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

#pragma mark -
#pragma mark MultiResourceRefreshToken Element Tests

- (void)testMultiResourceRefreshToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><MultiResourceRefreshToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertEqualObjects(item.refreshToken, @"i_am_a_refresh_token");
}

- (void)testMultiResourceRefreshToken_withNoAttributes_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><MultiResourceRefreshToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

#pragma mark -
#pragma mark FamilyRefreshToken element tests

- (void)testFamilyRefreshToken_withMinimalAttributes_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><FamilyRefreshToken token=\"i_am_a_refresh_token\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" familyId=\"1\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertEqualObjects(item.refreshToken, @"i_am_a_refresh_token");
}

- (void)testFamilyRefreshToken_withNoAttributes_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><FamilyRefreshToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

#pragma mark -
#pragma mark Token Attribute Tests

- (void)testNoToken_withAccessToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\"  tenant=\"mytenant\"/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
    
    XCTAssertTrue([GetReason(error) containsString:@"token"]);
}

- (void)testNoToken_withRefreshToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\"  tenant=\"mytenant\"/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
    
    XCTAssertTrue([GetReason(error) containsString:@"token"]);
}

- (void)testNoToken_withMultiResourceRefreshToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\"/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
    
    XCTAssertTrue([GetReason(error) containsString:@"token"]);
}
- (void)testNoToken_withFamilyRefreshToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken familyId=\"1\" authority=\"https://iamanauthority.com\" enant=\"mytenant\"/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
    
    XCTAssertTrue([GetReason(error) containsString:@"token"]);
}

- (void)testTokenSubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"$(token)\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" /></Cache>"];
    
    loader.testVariables = [@{ @"token" : @"subaccesstoken" } mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item.accessToken, @"subaccesstoken");
}


#pragma mark -
#pragma mark ClientID Attribute Tests

- (void)testCache_whenRefreshTokenNoClientId_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testClientIdSubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"$(clientId)\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" /></Cache>"];
    
    loader.testVariables = [@{ @"clientId" : @"subclientid" } mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item.clientId, @"subclientid");
}

#pragma mark -
#pragma mark Resource Attribute Tests

- (void)testCache_withAccessTokenNoResource_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testResourceSubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"$(resource)\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" /></Cache>"];
    
    loader.testVariables = [@{ @"resource" : @"subresource" } mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item.resource, @"subresource");
}

#pragma mark -
#pragma mark Authority Attribute Tests

- (void)testNoAuthority_withRefreshToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testAuthorityNotURL_withRefreshToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"iamnotanauthority88(&@#@#$R12343\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testAuthoritySubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"$(authority)\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" /></Cache>"];
    
    loader.testVariables = [@{ @"authority" : @"https://subauthority.com"} mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item.authority, @"https://subauthority.com");
}

#pragma mark -
#pragma mark ID Token Attribute Tests

- (void)testIdToken_withMRRT_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><MultiResourceRefreshToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertEqualObjects(item.refreshToken, @"i_am_a_refresh_token");
    XCTAssertEqualObjects(item.userInformation.userId, @"user@contoso.com");
}

- (void)testIdToken_withAccessToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    XCTAssertEqualObjects(cache[0].userInformation.userId, @"user@contoso.com");
}

- (void)testBadIdToken_withAccessToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"asdasiudhy2098134ujijsad0897ny89ashujdoiajhdsoiukjhn098sd=-0123=uji9kaosdenlkiasdlk\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
}

- (void)testIdTokenSubstitution_withAccessToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"$(idtoken)\" tenant=\"mytenant\" /></Cache>"];
    
    loader.testVariables = [@{ @"idtoken" : @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0"} mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    XCTAssertEqualObjects(cache[0].userInformation.userId, @"user@contoso.com");
}

#pragma mark -
#pragma mark ExpiresIn Attribute Tests


- (void)testNoExpiresIn_withAccessToken_shouldDefaultTo3600
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item.expiresOn);
    XCTAssertEqualWithAccuracy(item.expiresOn.timeIntervalSinceNow, 3600.0, 5.0);
}

- (void)testExpiresIn_withAccessToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" expiresIn=\"60\" tenant=\"mytenant\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item.expiresOn);
    XCTAssertEqualWithAccuracy(item.expiresOn.timeIntervalSinceNow, 60.0, 5.0);
}

- (void)testExpiresInSubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"mytenant\" expiresIn=\"$(expiresIn)\" /></Cache>"];
    
    loader.testVariables = [@{ @"expiresIn" : @"90" } mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    ADTokenCacheItem *item = cache[0];
    XCTAssertNotNil(item);
    XCTAssertEqualWithAccuracy(item.expiresOn.timeIntervalSinceNow, 90.0, 5.0);
}



#pragma mark -
#pragma mark Tenant Attribute Tests

- (void)testTenantSubstitution_withAccessToken_shouldPass
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" tenant=\"$(tenant)\" /></Cache>"];
    
    loader.testVariables = [@{ @"tenant" : @"subtenant" } mutableCopy];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray<ADTokenCacheItem *> *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
    
    // Tenant doesn't get used in objC so we don't have anything to check for here, other platforms will want to check.
}

- (void)testTenantMissing_withAccessToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" idToken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" /></Cache>"];
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    XCTAssertTrue([GetReason(error) containsString:@"tenant"]);
}

@end

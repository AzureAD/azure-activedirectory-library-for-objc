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

- (void)testCache_basicSingleResourceRefreshToken_shouldSucceed
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

- (void)testCache_basicMultiResourceRefreshToken_shouldSucceed
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

- (void)testCache_MRRTWithIdToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><MultiResourceRefreshToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" tenant=\"mytenant\" idtoken=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0\" /></Cache>"];
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

- (void)testCache_whenRefreshTokenNoAttributes_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken/></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}


- (void)testCache_whenRefreshTokenNoToken_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

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

- (void)testCache_whenRefreshTokenNoAuthority_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testCache_whenRefreshTokenAuthorityNotURL_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"iamnotanauthority88(&@#@#$R12343\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
    
}

- (void)testCache_whenAccessTokenNoResource_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testCache_whenAccessTokenWithExpiresIn_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><AccessToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" resource=\"resource\" expiresIn=\"60\" tenant=\"mytenant\" /></Cache>"];
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

@end

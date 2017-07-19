//
//  ADTestLoaderCacheTests.m
//  ADAL
//
//  Created by Ryan Pangrle on 7/19/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "ADTestLoader.h"

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

- (void)testCache_basicSingleResourceRefreshToken_shouldSucceed
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
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
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNotNil(cache);
    XCTAssertEqual(cache.count, 1);
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
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testCache_whenRefreshTokenNoClientId_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    NSArray *cache = loader.cacheItems;
    XCTAssertNil(cache);
}

- (void)testCache_whenRefreshTokenNoAuthority_shouldFail
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<Cache><RefreshToken token=\"i_am_a_refresh_token\" resource=\"resource\" clientId=\"clientid\" authority=\"https://iamanauthority.com\" /></Cache>"];
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

@end

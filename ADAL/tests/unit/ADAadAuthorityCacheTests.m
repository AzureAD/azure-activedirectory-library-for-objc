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

#import "ADAadAuthorityCache.h"

#include <pthread.h>

@interface ADAadAuthorityCache (TestUtils)

- (NSDictionary<NSString *, ADAadAuthorityCacheRecord *> *)recordMap;
- (void)setRecordMap:(NSDictionary<NSString *, ADAadAuthorityCacheRecord *> *)cacheDictionary;

- (BOOL)grabReadLock;
- (BOOL)grabWriteLock;
- (BOOL)tryWriteLock;
- (BOOL)unlock;

@end

@implementation ADAadAuthorityCache (TestUtils)

- (NSDictionary<NSString *, ADAadAuthorityCacheRecord *> *)recordMap
{
    return _recordMap;
}

- (void)setRecordMap:(NSDictionary<NSString *, ADAadAuthorityCacheRecord *> *)cacheDictionary
{
    _recordMap = [cacheDictionary mutableCopy];
}

- (BOOL)grabWriteLock
{
    return 0 == pthread_rwlock_wrlock(&_rwLock);
}

- (BOOL)tryWriteLock
{
    return 0 == pthread_rwlock_trywrlock(&_rwLock);
}

- (BOOL)grabReadLock
{
    return 0 == pthread_rwlock_rdlock(&_rwLock);
}

- (BOOL)unlock
{
    return 0 == pthread_rwlock_unlock(&_rwLock);
}

@end

@interface ADAadAuthorityCacheTests : ADTestCase

@end

@implementation ADAadAuthorityCacheTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

// Test cases testing the test utilities! It's test-ception!
- (void)testCheckCache_whenNilNoCache_shouldReturnNil
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    
    XCTAssertNil([cache checkCache:nil]);
    // We do a try write lock check here to make sure that no one is still holding onto the lock
    // after this is done.
    XCTAssertTrue([cache tryWriteLock]);
}

- (void)testCheckCache_whenWhitespaceStringhNoCache_shouldReturnNoRecordNoLock
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    
    XCTAssertNil([cache checkCache:[NSURL URLWithString:@"  "]]);
    XCTAssertTrue([cache tryWriteLock]);
}

- (void)testCheckCache_whenValidURLNoCache_shouldReturnNoRecordNoLock
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    
    XCTAssertNil([cache checkCache:[NSURL URLWithString:@"https://somedomain.com"]]);
    XCTAssertTrue([cache tryWriteLock]);
}

- (void)testCheckCache_whenNotValidCached_shouldReturnNonValidRecordNoLock
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"somedomain.com" : [ADAadAuthorityCacheRecord new] };
    
    ADAadAuthorityCacheRecord *record = [cache checkCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertTrue([cache tryWriteLock]);
}

- (void)testTryCheckCache_whenNotValidCached_shouldReturnNonValidRecordNoLock
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"somedomain.com" : [ADAadAuthorityCacheRecord new] };
    
    ADAadAuthorityCacheRecord *record = [cache tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertTrue([cache tryWriteLock]);
}

- (void)testTryCheckCache_whenNotValidCacheReadLockHeld_shouldReturnNonValidRecordNoLock
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"somedomain.com" : [ADAadAuthorityCacheRecord new] };
    XCTAssertTrue([cache grabReadLock]);
    
    // tryCheckCache should still be able to read the cache even if the read lock is being held
    ADAadAuthorityCacheRecord *record = [cache tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
}

- (void)testTryCheckCache_whenNotValidCacheReadLockHeld_shouldReturnNil
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"somedomain.com" : [ADAadAuthorityCacheRecord new] };
    XCTAssertTrue([cache grabWriteLock]);
    
    // The write lock prevents any readers until it gets unlocked, so this should prevent tryCheckCache
    // from accessing the cache and it should immediately return nil.
    ADAadAuthorityCacheRecord *record = [cache tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNil(record);
}

#pragma mark -
#pragma mark Network URL Utility Tests

- (void)testNetworkUrlForAuthority_whenNotCached_shouldReturnNil
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache networkUrlForAuthority:authority];
    
    XCTAssertNil(cachedAuthority);
}

- (void)testNetworkUrlForAuthority_whenCachedNotValid_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"fakeauthority.com" : [ADAadAuthorityCacheRecord new] };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache networkUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testNetworkUrlForAuthority_whenCachedValidNoPreferredNetwork_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache networkUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testNetworkUrlForAuthority_whenCachedValidSamePreferredNetwork_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    record.networkHost = @"fakeauthority.com";
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache networkUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testNetworkUrlForAuthority_whenCachedValidDifferentPreferredNetwork_shouldReturnPreferredURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    record.networkHost = @"preferredauthority.com";
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSURL *expectedAuthority = [NSURL URLWithString:@"https://preferredauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache networkUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(expectedAuthority, cachedAuthority);
}

#pragma mark -
#pragma mark Cache URL Utility Tests

- (void)testCacheUrlForAuthority_whenNotCached_shouldReturnNil
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache cacheUrlForAuthority:authority];
    
    XCTAssertNil(cachedAuthority);
}

- (void)testCacheUrlForAuthority_whenCachedNotValid_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    cache.recordMap = @{ @"fakeauthority.com" : [ADAadAuthorityCacheRecord new] };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache cacheUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testCacheUrlForAuthority_whenCachedValidNoPreferredCache_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache cacheUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testCacheUrlForAuthority_whenCachedValidSameCacheNetwork_shouldReturnSameURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    record.cacheHost = @"fakeauthority.com";
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache cacheUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(authority, cachedAuthority);
}

- (void)testCacheUrlForAuthority_whenCachedValidDifferentPreferredNetwork_shouldReturnPreferredURL
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    __auto_type record = [ADAadAuthorityCacheRecord new];
    record.validated = YES;
    record.cacheHost = @"preferredauthority.com";
    cache.recordMap = @{ @"fakeauthority.com" : record };
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSURL *expectedAuthority = [NSURL URLWithString:@"https://preferredauthority.com/v2/oauth/endpoint"];
    
    NSURL *cachedAuthority = [cache cacheUrlForAuthority:authority];
    
    XCTAssertNotNil(cachedAuthority);
    XCTAssertEqualObjects(expectedAuthority, cachedAuthority);
}

#pragma mark -
#pragma mark Process Metadata tests

- (void)testProcessMetadata_whenNilMetadata_shouldCreateDefaultEntry
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedHost = @"fakeauthority.com";
    
    ADAuthenticationError *error = nil;
    XCTAssertTrue([cache processMetadata:nil authority:authority context:nil error:&error]);
    
    XCTAssertNil(error);
    __auto_type map = cache.recordMap;
    XCTAssertNotNil(map);
    XCTAssertEqual(map.count, 1);
    __auto_type record = map[expectedHost];
    XCTAssertNotNil(record);
    XCTAssertEqualObjects(expectedHost, record.networkHost);
    XCTAssertEqualObjects(expectedHost, record.cacheHost);
    XCTAssertNil(record.aliases);
}

- (void)testProcessMetadata_whenMetadataProvided_shouldCreateExpectedRecords
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedHost = @"fakeauthority.com";
    NSString *expectedNetworkHost = @"fakeauthority.net";
    NSString *expectedCacheHost = @"sts.fakeauthority.com";
    NSArray *expectedAliases = @[ expectedHost, expectedCacheHost, expectedNetworkHost ];
    NSArray *metadata = @[ @{ @"preferred_network" : expectedNetworkHost,
                              @"preferred_cache" :  expectedCacheHost,
                              @"aliases" : expectedAliases } ];
    
    ADAuthenticationError *error = nil;
    XCTAssertTrue([cache processMetadata:metadata authority:authority context:nil error:&error]);
    
    XCTAssertNil(error);
    __auto_type map = cache.recordMap;
    XCTAssertNotNil(map);
    // A record should be created for each of the aliases, and each of those records should be
    // identical
    XCTAssertEqual(map.count, 3);
    __auto_type record = map[expectedHost];
    XCTAssertNotNil(record);
    XCTAssertEqualObjects(expectedNetworkHost, record.networkHost);
    XCTAssertEqualObjects(expectedCacheHost, record.cacheHost);
    XCTAssertEqualObjects(expectedAliases, record.aliases);
    record = map[expectedNetworkHost];
    XCTAssertNotNil(record);
    XCTAssertEqualObjects(expectedNetworkHost, record.networkHost);
    XCTAssertEqualObjects(expectedCacheHost, record.cacheHost);
    XCTAssertEqualObjects(expectedAliases, record.aliases);
    record = map[expectedCacheHost];
    XCTAssertNotNil(record);
    XCTAssertEqualObjects(expectedNetworkHost, record.networkHost);
    XCTAssertEqualObjects(expectedCacheHost, record.cacheHost);
    XCTAssertEqualObjects(expectedAliases, record.aliases);
}


- (void)testProcessMetadata_whenBadMetadataWrongNetworkHostType_shouldReturnErrorCreateNoRecords
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedHost = @"fakeauthority.com";
    NSString *expectedNetworkHost = @"fakeauthority.net";
    NSString *expectedCacheHost = @"sts.fakeauthority.com";
    NSArray *expectedAliases = @[ expectedHost, expectedCacheHost, expectedNetworkHost ];
    NSArray *metadata = @[ @{ @"preferred_network" : @1,
                              @"preferred_cache" :  expectedCacheHost,
                              @"aliases" : expectedAliases } ];
    
    ADAuthenticationError *error = nil;
    XCTAssertFalse([cache processMetadata:metadata authority:authority context:nil error:&error]);
    
    
    // Verify the correct error code is returned and no records were added to the cache
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_SERVER_INVALID_RESPONSE);
    XCTAssertEqual(cache.recordMap.count, 0);
}

- (void)testProcessMetadata_whenBadMetadataWrongCacheHostType_shouldReturnErrorCreateNoRecords
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedHost = @"fakeauthority.com";
    NSString *expectedNetworkHost = @"fakeauthority.net";
    NSString *expectedCacheHost = @"sts.fakeauthority.com";
    NSArray *expectedAliases = @[ expectedHost, expectedCacheHost, expectedNetworkHost ];
    NSArray *metadata = @[ @{ @"preferred_network" : expectedNetworkHost,
                              @"preferred_cache" :  @1,
                              @"aliases" : expectedAliases } ];
    
    ADAuthenticationError *error = nil;
    XCTAssertFalse([cache processMetadata:metadata authority:authority context:nil error:&error]);
    
    
    // Verify the correct error code is returned and no records were added to the cache
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_SERVER_INVALID_RESPONSE);
    XCTAssertEqual(cache.recordMap.count, 0);
}

- (void)testProcessMetadata_whenBadMetadataWrongAliasesType_shouldReturnErrorCreateNoRecords
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedNetworkHost = @"fakeauthority.net";
    NSString *expectedCacheHost = @"sts.fakeauthority.com";
    NSArray *metadata = @[ @{ @"preferred_network" : expectedNetworkHost,
                              @"preferred_cache" :  expectedCacheHost,
                              @"aliases" : @1 } ];
    
    ADAuthenticationError *error = nil;
    XCTAssertFalse([cache processMetadata:metadata authority:authority context:nil error:&error]);
    
    
    // Verify the correct error code is returned and no records were added to the cache
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_SERVER_INVALID_RESPONSE);
    XCTAssertEqual(cache.recordMap.count, 0);
}

- (void)testProcessMetadata_whenBadMetadataWrongTypeInAliases_shouldReturnErrorCreateNoRecords
{
    ADAadAuthorityCache *cache = [[ADAadAuthorityCache alloc] init];
    NSURL *authority = [NSURL URLWithString:@"https://fakeauthority.com/v2/oauth/endpoint"];
    NSString *expectedHost = @"fakeauthority.com";
    NSString *expectedNetworkHost = @"fakeauthority.net";
    NSString *expectedCacheHost = @"sts.fakeauthority.com";
    NSArray *expectedAliases = @[ expectedHost, @1, expectedNetworkHost ];
    NSArray *metadata = @[ @{ @"preferred_network" : expectedNetworkHost,
                              @"preferred_cache" :  expectedCacheHost,
                              @"aliases" : expectedAliases } ];
    
    ADAuthenticationError *error = nil;
    XCTAssertFalse([cache processMetadata:metadata authority:authority context:nil error:&error]);
    
    
    // Verify the correct error code is returned and no records were added to the cache
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_SERVER_INVALID_RESPONSE);
    XCTAssertEqual(cache.recordMap.count, 0);
}


@end

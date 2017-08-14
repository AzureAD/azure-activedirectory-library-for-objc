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


#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult.h"
#import "ADAuthorityValidation.h"
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLSession.h"

#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"

#import "NSURL+ADExtensions.h"

#import "XCTestCase+TestHelperMethods.h"
#import <XCTest/XCTest.h>

#include <pthread.h>

@interface ADAuthorityValidation (TestUtils)

- (void)setAADValidationCache:(NSDictionary<NSString *, ADAuthorityValidationAADRecord *> *)cacheDictionary;

- (BOOL)grabReadLock;
- (BOOL)grabWriteLock;
- (BOOL)tryWriteLock;
- (BOOL)unlock;

@end


@implementation ADAuthorityValidation (TestUtils)

- (void)setAADValidationCache:(NSDictionary<NSString *, ADAuthorityValidationAADRecord *> *)cacheDictionary
{
    _aadValidationCache = [cacheDictionary mutableCopy];
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

@interface ADAuthortyValidationTests : ADTestCase

@end

@implementation ADAuthortyValidationTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

// Test cases testing the test utilities! It's test-ception!
- (void)testCheckCache_whenNilNoCache_shouldReturnNil
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    
    XCTAssertNil([av checkCache:nil context:nil]);
    // We do a try write lock check here to make sure that no one is still holding onto the lock
    // after this is done.
    XCTAssertTrue([av tryWriteLock]);
}

- (void)testCheckCache_whenWhitespaceStringhNoCache_shouldReturnNil
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    
    XCTAssertNil([av checkCache:[NSURL URLWithString:@"  "] context:nil]);
    XCTAssertTrue([av tryWriteLock]);
}

- (void)testCheckCache_whenValidURLNoCache_shouldReturnNil
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    
    XCTAssertNil([av checkCache:[NSURL URLWithString:@"https://somedomain.com"] context:nil]);
    XCTAssertTrue([av tryWriteLock]);
}

- (void)testCheckCache_whenNotValidCached_shouldReturnRecord
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    av.AADValidationCache = @{ @"somedomain.com" : [ADAuthorityValidationAADRecord new] };
    
    ADAuthorityValidationAADRecord *record = [av checkCache:[NSURL URLWithString:@"https://somedomain.com"] context:nil];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertTrue([av tryWriteLock]);
}

- (void)testTryCheckCache_whenNotValidCached_shouldReturnRecord
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    av.AADValidationCache = @{ @"somedomain.com" : [ADAuthorityValidationAADRecord new] };
    
    ADAuthorityValidationAADRecord *record = [av tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertTrue([av tryWriteLock]);
}

- (void)testTryCheckCache_whenNotValidCacheReadLockHeld_shouldReturnRecord
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    av.AADValidationCache = @{ @"somedomain.com" : [ADAuthorityValidationAADRecord new] };
    XCTAssertTrue([av grabReadLock]);
    
    // tryCheckCache should still be able to read the cache even if the read lock is being held
    ADAuthorityValidationAADRecord *record = [av tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
}

- (void)testTryCheckCache_whenNotValidCacheReadLockHeld_shouldReturnNil
{
    ADAuthorityValidation *av = [[ADAuthorityValidation alloc] init];
    av.AADValidationCache = @{ @"somedomain.com" : [ADAuthorityValidationAADRecord new] };
    XCTAssertTrue([av grabWriteLock]);
    
    // The write lock prevents any readers until it gets unlocked, so this should prevent tryCheckCache
    // from accessing the cache and it should immediately return nil.
    ADAuthorityValidationAADRecord *record = [av tryCheckCache:[NSURL URLWithString:@"https://somedomain.com"]];
    
    XCTAssertNil(record);
}

- (void)testAdfsAuthorityValidated
{
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

- (void)testAddAdfsAuthority
{
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    [authorityValidation addValidAuthority:anotherHost domain:upnSuffix];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertTrue([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

@end

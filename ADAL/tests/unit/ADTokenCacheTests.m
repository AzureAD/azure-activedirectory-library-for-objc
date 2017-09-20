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
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADTokenCacheKey.h"
#import "NSString+ADHelperMethods.h"
#import "ADUserInformation.h"

#define TEST_AUTHORITY @"https://login.windows.net/contoso.com"
#define TEST_CLIENT_ID @"01234567-89ab-cdef-0123-456789abcdef"

typedef enum
{
    kNothingCalled,
    kWillCalled,
    kDidCalled,
} TestDelegateState;

@interface ADTestSimpleStorage : NSObject <ADTokenCacheDelegate>
{
@public
    BOOL _changed;
    
    NSData* _cache;
    
    TestDelegateState access;
    TestDelegateState write;
}

- (void)changeCache:(NSData*)cache;

@end

@implementation ADTestSimpleStorage

- (void)willAccessCache:(nonnull ADTokenCache *)cache
{
    if (_changed)
    {
        [cache deserialize:_cache error:nil];
        _changed = NO;
    }
    
    switch (access)
    {
        case kNothingCalled: access = kWillCalled; break;
        case kWillCalled: NSAssert(0, @"willAccessCache called multiple times without calling didAccessCache!"); break;
        case kDidCalled: access = kWillCalled; break;
    }
}

- (void)didAccessCache:(nonnull ADTokenCache *)cache
{
    (void)cache;
    
    switch (access)
    {
        case kNothingCalled: NSAssert(0, @"willAccessCache must be called before didAccessCache"); break;
        case kWillCalled: access = kDidCalled; break;
        case kDidCalled: NSAssert(0, @"didAccessCache callled multuple times!"); break;
    }
}

- (void)willWriteCache:(nonnull ADTokenCache *)cache
{
    if (_changed)
    {
        [cache deserialize:_cache error:nil];
        _changed = NO;
    }
    
    switch (write)
    {
        case kNothingCalled: write = kWillCalled; break;
        case kWillCalled: NSAssert(0, @"willAccessCache called multiple times without calling didAccessCache!"); break;
        case kDidCalled: write = kWillCalled; break;
    }
}

- (void)didWriteCache:(nonnull ADTokenCache *)cache
{
    _cache = [cache serialize];
    
    switch (write)
    {
        case kNothingCalled: NSAssert(0, @"willAccessCache must be called before didAccessCache"); break;
        case kWillCalled: write = kDidCalled; break;
        case kDidCalled: NSAssert(0, @"didAccessCache callled multuple times!"); break;
    }
    
}

- (void)changeCache:(NSData *)cache
{
    _cache = [cache copy];
    _changed = YES;
}

- (void)resetFlags
{
}

- (BOOL)verifyRead:(NSString**)failureReason
{
    switch (access)
    {
        case kNothingCalled: *failureReason = @"Neither willAccessCache or didAccessCache were called!"; return NO;
        case kWillCalled: *failureReason = @"willAccessCache was called without a matching didAccessCache call."; return NO;
        case kDidCalled: return YES;
    }
}

- (BOOL)verifyWrite:(NSString**)failureReason
{
    switch (write)
    {
        case kNothingCalled: *failureReason = @"Neither willWriteCache or didWriteCache were called!"; return NO;
        case kWillCalled: *failureReason = @"willWriteCache was called without a matching didWriteCache call."; return NO;
        case kDidCalled: return YES;
    }
}

@end

static NSString* ReginaUserid()
{
    return @"regina@contoso.com";
}

static NSString* ReginaIdtoken()
{
    NSDictionary* part1_claims = @{ @"aud" : @"c3c7f5e5-7153-44d4-90e6-329686d48d76",
                                    @"iss" : @"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                    @"iat" : @"1387224169",
                                    @"nbf" : @"1387224169",
                                    @"exp" : @"1387227769" };
    
    NSDictionary* idtoken_claims = @{ @"ver" : @"1.0",
                                      @"tid" : @"6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                      @"oid" : @"53c6acf2-2742-4538-918d-e78257ec8516",
                                      @"upn" : ReginaUserid(),
                                      @"unique_name" : @"regina@contoso.com",
                                      @"sub" : @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc",
                                      @"family_name" : @"George",
                                      @"given_name" : @"Regina"
                                      };
    
    NSString* idtoken = [NSString stringWithFormat:@"%@.%@",
                         [NSString adBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:part1_claims options:0 error:nil]],
                         [NSString adBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_claims options:0 error:nil]]];
    
    return idtoken;
}

static ADTokenCacheItem* ReginaItem(NSString* resource)
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.userInformation = [ADUserInformation userInformationWithIdToken:ReginaIdtoken() error:nil];
    item.authority = TEST_AUTHORITY;
    item.accessToken = @"ThisIsMyAcessToken";
    item.refreshToken = @"ThisIsMyRefreshToken";
    item.accessTokenType = @"Bearer";
    item.resource = resource;
    item.clientId = TEST_CLIENT_ID;
    
    return item;
}

static ADTokenCacheKey* CacheKey(NSString* resource)
{
    return [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY resource:resource clientId:TEST_CLIENT_ID error:nil];
}

static NSString* CartmanUserid()
{
    return @"cartman@contoso.com";
}

static NSString* CartmanIdtoken()
{
    NSDictionary* idtoken_part1 = @{ @"aud" : @"123456789",
                                     @"iss" : @"123456789" };
    NSDictionary* idtoken_part2 = @{ @"ver" : @"1.0",
                                     @"tid" : @"12345678-a94c-4335-889b-6c598e6d8048",
                                     @"oid" : @"90abcdef-2742-4538-918d-e78257ec8516",
                                     @"upn" : CartmanUserid(),
                                     @"unique_name" : @"cartman@contoso.com",
                                     @"sub" : @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc",
                                     @"family_name" : @"Eric",
                                     @"given_name" : @"Cartman" };
    
    NSString* idtoken = [NSString stringWithFormat:@"%@.%@",
                         [NSString adBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_part1 options:0 error:nil]],
                         [NSString adBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_part2 options:0 error:nil]]];
    
    return idtoken;
}

static ADTokenCacheItem* CartmanItem(NSString* resource)
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = resource;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = @"Grant me access, hippie!";
    item.accessTokenType = @"Bearer";
    item.refreshToken = @"I am a refresh token.";
    item.userInformation = [ADUserInformation userInformationWithIdToken:CartmanIdtoken() error:nil];
    
    return item;
}

@interface ADTokenCache (TestUtil)

- (void)setCache:(NSMutableDictionary*)cache;

@end

@implementation ADTokenCache (TestUtil)

- (void)setCache:(NSMutableDictionary *)cache
{
    _cache = cache;
}

- (NSDictionary *)cache
{
    return _cache;
}

@end


@interface ADTokenCacheTests : ADTestCase

@end

@implementation ADTokenCacheTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

#pragma mark -
#pragma mark ADTokenCacheStorageWrapper Unit Tests
#pragma mark Data Validation

- (void)testValidationNil
{
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Even though tokenCache is empty we're still expecting this to come up good.
    XCTAssertFalse([wrapper validateCache:nil error:&error]);
    XCTAssertNotNil(error);
}

- (void)testValidationEmptyDictionary
{
    NSDictionary* root = @{};
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Even though tokenCache is empty we're still expecting this to come up good.
    XCTAssertFalse([wrapper validateCache:root error:&error]);
    XCTAssertNotNil(error);
}

- (void)testValidationNoTokenCache
{
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Even though tokenCache is empty we're still expecting this to come up good.
    XCTAssertFalse([wrapper validateCache:root error:&error]);
    XCTAssertNotNil(error);
}


- (void)testValidationEmptyTokenCache
{
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : [NSMutableDictionary new] };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Even though tokenCache is empty we're still expecting this to come up good.
    XCTAssertTrue([wrapper validateCache:root error:&error]);
    XCTAssertNil(error);
}

- (void)testValidationTokenCacheNotMutable
{
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : [NSDictionary new] };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Even though tokenCache is empty we're still expecting this to come up good.
    XCTAssertFalse([wrapper validateCache:root error:&error]);
    XCTAssertNotNil(error);
}

- (void)testValidationEmptyTokens
{
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : [NSMutableDictionary new] }];
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : tokenCache };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Still expecting these too come back as "good"
    XCTAssertTrue([wrapper validateCache:root error:&error]);
    XCTAssertNil(error);
}

- (void)testValidationBadTokensNotMutable
{
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : [NSDictionary new]}];
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : tokenCache };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Still expecting these too come back as "good"
    XCTAssertFalse([wrapper validateCache:root error:&error]);
    XCTAssertNotNil(error);
}

- (void)testValidationTokensAndIdtokens
{
    ADAuthenticationError* error = nil;
    
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge"),
                                             CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge"),
                                            CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty"),
                                            CacheKey(@"popularity") : ReginaItem(@"popularity"),
                                            CacheKey(@"kaltein_bar") : ReginaItem(@"kaltein_bar"),
                                            CacheKey(@"friends") : ReginaItem(@"friends")}];
    NSMutableDictionary* tokens = [NSMutableDictionary dictionaryWithDictionary:
                                   @{ CartmanUserid() : cartmanTokens,
                                      ReginaUserid() : reginaTokens}];
    
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : tokens }];
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : tokenCache };
    
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Still expecting these too come back as "good"
    XCTAssertTrue([wrapper validateCache:root error:&error]);
    XCTAssertNil(error);
}

#pragma mark ADTokenCacheEnumerator Implementation

- (void)testGetItemWithKeyUserId
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Populate the cache dictionaries
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens }];
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* expectedItem = CartmanItem(@"mister_kitty");
    ADTokenCacheItem* actualItem = [wrapper getItemWithKey:CacheKey(@"mister_kitty") userId:CartmanUserid() correlationId:nil error:&error];
    XCTAssertNotNil(actualItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(expectedItem, actualItem);
}

- (void)testAllItemsSingleItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Populate the cache dictionaries
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens }];
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    NSArray* items = [wrapper allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqualObjects(items, @[CartmanItem(@"mister_kitty")]);
}

- (void)testAllItems
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge"),
                                             CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"popularity") : ReginaItem(@"popularity"),
                                            CacheKey(@"kaltein_bar") : ReginaItem(@"kaltein_bar"),
                                            CacheKey(@"friends") : ReginaItem(@"friends")}];
    NSMutableDictionary* tokens = [NSMutableDictionary dictionaryWithDictionary:
                                   @{ CartmanUserid() : cartmanTokens,
                                      ReginaUserid() : reginaTokens}];
    
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : tokens }];
    
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    NSArray* items = [wrapper allItems:&error];
    NSArray* expected = @[ CartmanItem(@"police_badge"), CartmanItem(@"mister_kitty"),
                           ReginaItem(@"popularity"), ReginaItem(@"kaltein_bar"),
                           ReginaItem(@"friends") ];
    XCTAssertNotNil(items);
    XCTAssertEqual(items.count, 5);
    XCTAssertNil(error);
    
    // Turn the items into to a set so we can just compare object equality without having to worry about order
    NSSet* actualSet = [NSSet setWithArray:items];
    NSSet* expectedSet = [NSSet setWithArray:expected];
    
    // If you're seeing this check fail and you can't come up with a good reason why that might be take a
    // good long look at the hash calculating in ADTokenCacheItem. NSSet relies on -hash to be implemented
    // correctly for -isEqual: to work properly.
    XCTAssertEqualObjects(actualSet, expectedSet);
}

#if 0
- (void)testGetItemsWithKey
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"friends") : CartmanItem(@"friends") } ];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"friends") : ReginaItem(@"friends")}];
    NSMutableDictionary* tokens = [NSMutableDictionary dictionaryWithDictionary:
                                   @{ CartmanUserid() : cartmanTokens,
                                      ReginaUserid() : reginaTokens}];
    
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : tokens,
                                          @"idtokens" : idtokens }];
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    NSArray* items = [wrapper getItemsWithKey:CacheKey(@"friends") userId:nil error:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    
    NSSet* expectedSet = [NSSet setWithArray:@[CartmanItem(@"friends"), ReginaItem(@"friends", YES)]];
    NSSet* actualSet = [NSSet setWithArray:items];
    XCTAssertEqualObjects(expectedSet, actualSet);
}

#endif

- (void)testAddItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    XCTAssertNil([wrapper cache]);
    
    ADAuthenticationError* error = nil;
    [wrapper addOrUpdateItem:CartmanItem(@"mister_kitty") correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Expected cache structure
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens }];
    
    XCTAssertEqualObjects(tokenCache, [wrapper cache]);
}


- (void)testRemoveItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Populate the cache dictionaries
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty") }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens }];
    [wrapper setCache:tokenCache];

    ADAuthenticationError* error = nil;
    
    [wrapper removeItem:CartmanItem(@"mister_kitty") error:&error];
    XCTAssertNil(error);
    
    NSMutableDictionary* expected = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ @"tokens" : [NSMutableDictionary new] }];
    
    XCTAssertEqualObjects([wrapper cache], expected);
}

#pragma mark -
#pragma mark ADCacheStorage Integration Tests


// This test creates two different storage wrappers. Adds an item into the first, and then copies the backing
// store to the second wrapper and make sure the item gets through.
- (void)testAddItemAllItems
{
    ADAuthenticationError* error = nil;
    ADTestSimpleStorage* storage1 = [[ADTestSimpleStorage alloc] init];
    ADTokenCache* wrapper1 = [ADTokenCache new];
    [wrapper1 setDelegate:storage1];
    
    ADTestSimpleStorage* storage2 = [[ADTestSimpleStorage alloc] init];
    ADTokenCache* wrapper2 = [ADTokenCache new];
    [wrapper2 setDelegate:storage2];
    
    
    // Make sure both wrappers start off showing empty and that they checked for updates
    XCTAssertNil([wrapper1 allItems:&error]);
    XCTAssertNil(error);
    
    XCTAssertNil([wrapper2 allItems:&error]);
    XCTAssertNil(error);
    
    ADTokenCacheItem* item1 = ReginaItem(@"popularity");
    // Add an item into wrapper 1
    
    [wrapper1 addOrUpdateItem:item1 correlationId:nil error:&error];
    XCTAssertNotNil(storage1->_cache);
    NSString* failureReason = nil;
    XCTAssertTrue([storage1 verifyWrite:&failureReason], @"addOrUpdateItem didn't use the delegate correctly: %@", failureReason);
    
    NSArray* items = nil;
    
    // Make sure the item shows up in allItems
    items = [wrapper1 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertTrue([storage1 verifyRead:&failureReason], @"allItems didn't use the delegate correctly: %@", failureReason);
    
    XCTAssertEqual(items.count, 1);
    XCTAssertEqualObjects(items[0], item1);
    
    // Make sure the pointers are *not* equal (we want to make sure it's a copy,
    // a reference, just in case something in the item changes)
    XCTAssertNotEqual(items[0], item1);
    [storage1 resetFlags];

    // Copy the data from storage 1 into storage 2 "under the covers"
    [storage2 changeCache:[storage1->_cache copy]];
    
    // Call allItems and make sure it picks up on the cache change and shows us the item
    items = [wrapper2 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    XCTAssertEqualObjects(items[0], item1);
    
    // Add a second item into the storage with the information as the first and make sure it shows up in all items.
    ADTokenCacheItem* item2 = [item1 copy];
    
    // We're modifying item1 to make sure that it doesn't show up in the allItems array
    item1.resource = @"Stop";
    [wrapper1 addOrUpdateItem:item1 correlationId:nil error:&error];
    XCTAssertNil(error);

    items = [wrapper1 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 2);
    
    // Make sure both of the items are in the array
    XCTAssertTrue([items[0] isEqual:item1] || [items[1] isEqual:item1], @"Item1 wasn't found in allItems!");
    XCTAssertTrue([items[0] isEqual:item2] || [items[1] isEqual:item2], @"Item2 wasn't found in allItems!");
} 

@end

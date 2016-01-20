//
//  ADTokenCacheStorageWrapperTests.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ADCacheStorage.h"
#import "ADTokenCache.h"
#import "ADTokenCacheItem.h"
#import "ADTokenCacheStoreKey.h"
#import "NSString+ADHelperMethods.h"
#import "ADUserInformation.h"

#define TEST_AUTHORITY @"https://login.windows.net/contoso.com"
#define TEST_CLIENT_ID @"01234567-89ab-cdef-0123-456789abcdef"

@interface ADTestSimpleStorage : NSObject <ADCacheStorageDelegate>
{
@public
    BOOL _changed;
    BOOL _retrieveStorageCalled;
    BOOL _retrieveIfUpdatedCalled;
    
    NSData* _cache;
}

- (void)changeCache:(NSData*)cache;
- (void)resetFlags;

@end

@implementation ADTestSimpleStorage

/*!
 Called on initial storage retrieval
 */
- (BOOL)retrieveStorage:(NSData * __nonnull * __nullable)data
                  error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    (void)error;
    _changed = NO;
    _retrieveStorageCalled = YES;
    *data = _cache;
    return YES;
}

/*!
 Called when checking if the cache needs to be updated, return nil if nothing has changed since the last storage operation.
 Can be the same implementation as -retrieveStorage, however performance will suffer.
 */
- (BOOL)retrieveIfUpdated:(NSData **)data
                    error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    (void)error;
    _retrieveIfUpdatedCalled = YES;
    if (_changed)
    {
        _changed = NO;
        *data = _cache;
        return YES;
    }
    
    return YES;
}

/*!
 Called by ADAL to update the cache storage
 */
- (BOOL)saveToStorage:(nullable NSData*)data
                error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
{
    _cache = data;
    _changed = NO;
    
    return YES;
}

- (void)changeCache:(NSData *)cache
{
    _cache = cache;
    _changed = YES;
}

- (void)resetFlags
{
    _retrieveIfUpdatedCalled = NO;
    _retrieveStorageCalled = NO;
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
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:part1_claims options:0 error:nil]],
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_claims options:0 error:nil]]];
    
    return idtoken;
}

static ADTokenCacheItem* ReginaItem(NSString* resource, BOOL includeUserInfo)
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    if (includeUserInfo)
    {
        item.userInformation = [ADUserInformation userInformationWithIdToken:ReginaIdtoken() error:nil];
    }
    item.authority = TEST_AUTHORITY;
    item.accessToken = @"ThisIsMyAcessToken";
    item.refreshToken = @"ThisIsMyRefreshToken";
    item.accessTokenType = @"Bearer";
    item.resource = resource;
    item.clientId = TEST_CLIENT_ID;
    
    return item;
}

static ADTokenCacheStoreKey* CacheKey(NSString* resource)
{
    return [ADTokenCacheStoreKey keyWithAuthority:TEST_AUTHORITY resource:resource clientId:TEST_CLIENT_ID error:nil];
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
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_part1 options:0 error:nil]],
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_part2 options:0 error:nil]]];
    
    return idtoken;
}

static ADTokenCacheItem* CartmanItem(NSString* resource, BOOL includeUserInfo)
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = resource;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = @"Grant me access, hippie!";
    item.accessTokenType = @"Bearer";
    item.refreshToken = @"I am a refresh token.";
    if (includeUserInfo)
    {
        item.userInformation = [ADUserInformation userInformationWithIdToken:CartmanIdtoken() error:nil];
    }
    
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


@interface ADTokenCacheTests : XCTestCase

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
                                       @{ @"tokens"  : [NSMutableDictionary new],
                                          @"idtokens" : [NSMutableDictionary new] }];
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
                                       @{ @"tokens"  : [NSDictionary new],
                                          @"idtokens" : [NSMutableDictionary new] }];
    NSDictionary* root = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                            @"tokenCache" : tokenCache };
    
    ADAuthenticationError* error = nil;
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Still expecting these too come back as "good"
    XCTAssertFalse([wrapper validateCache:root error:&error]);
    XCTAssertNotNil(error);
}

- (void)testValidationBadIdtokensNotMutable
{
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : [NSMutableDictionary new],
                                          @"idtokens" : [NSDictionary new] }];
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
    
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:@{ CartmanUserid() : CartmanIdtoken(),
                                                                                     ReginaUserid() : ReginaIdtoken()}];
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge", NO),
                                             CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge", NO),
                                            CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO),
                                            CacheKey(@"popularity") : ReginaItem(@"popularity", NO),
                                            CacheKey(@"kaltein_bar") : ReginaItem(@"kaltein_bar", NO),
                                            CacheKey(@"friends") : ReginaItem(@"friends", NO)}];
    NSMutableDictionary* tokens = [NSMutableDictionary dictionaryWithDictionary:
                                   @{ CartmanUserid() : cartmanTokens,
                                      ReginaUserid() : reginaTokens}];
    
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : tokens,
                                          @"idtokens" : idtokens }];
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
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken() }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens,
                                          @"idtokens" : idtokens }];
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* expectedItem = CartmanItem(@"mister_kitty", YES);
    ADTokenCacheItem* actualItem = [wrapper getItemWithKey:CacheKey(@"mister_kitty") userId:CartmanUserid() error:&error];
    XCTAssertNotNil(actualItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(expectedItem, actualItem);
}

- (void)testAllItemsSingleItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Populate the cache dictionaries
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken() }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens,
                                          @"idtokens" : idtokens }];
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    NSArray* items = [wrapper allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqualObjects(items, @[CartmanItem(@"mister_kitty", YES)]);
}

- (void)testAllItems
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];

    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken(),
                                        ReginaUserid() : ReginaIdtoken()}];
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"police_badge") : CartmanItem(@"police_badge", NO),
                                             CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"popularity") : ReginaItem(@"popularity", NO),
                                            CacheKey(@"kaltein_bar") : ReginaItem(@"kaltein_bar", NO),
                                            CacheKey(@"friends") : ReginaItem(@"friends", NO)}];
    NSMutableDictionary* tokens = [NSMutableDictionary dictionaryWithDictionary:
                                   @{ CartmanUserid() : cartmanTokens,
                                      ReginaUserid() : reginaTokens}];
    
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens"  : tokens,
                                          @"idtokens" : idtokens }];
    
    [wrapper setCache:tokenCache];
    
    ADAuthenticationError* error = nil;
    NSArray* items = [wrapper allItems:&error];
    NSArray* expected = @[ CartmanItem(@"police_badge", YES), CartmanItem(@"mister_kitty", YES),
                           ReginaItem(@"popularity", YES), ReginaItem(@"kaltein_bar", YES),
                           ReginaItem(@"friends", YES) ];
    XCTAssertNotNil(items);
    XCTAssertEqual(items.count, 5);
    XCTAssertNil(error);
    
    // Turn the items into to a set so we can just compare object equality without having to worry about order
    NSSet* actualSet = [NSSet setWithArray:items];
    NSSet* expectedSet = [NSSet setWithArray:expected];
    XCTAssertEqualObjects(actualSet, expectedSet);
}

- (void)testGetItemsWithKey
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken(),
                                        ReginaUserid() : ReginaIdtoken()}];
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"friends") : CartmanItem(@"friends", NO) } ];
    NSMutableDictionary* reginaTokens = [NSMutableDictionary dictionaryWithDictionary:
                                         @{ CacheKey(@"friends") : ReginaItem(@"friends", NO)}];
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
    
    NSSet* expectedSet = [NSSet setWithArray:@[CartmanItem(@"friends", YES), ReginaItem(@"friends", YES)]];
    NSSet* actualSet = [NSSet setWithArray:items];
    XCTAssertEqualObjects(expectedSet, actualSet);
}

- (void)testAddItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    XCTAssertNil([wrapper cache]);
    
    ADAuthenticationError* error = nil;
    [wrapper addOrUpdateItem:CartmanItem(@"mister_kitty", YES) error:&error];
    XCTAssertNil(error);
    
    // Expected cache structure
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken() }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens,
                                          @"idtokens" : idtokens }];
    
    XCTAssertEqualObjects(tokenCache, [wrapper cache]);
}


- (void)testRemoveItem
{
    ADTokenCache* wrapper = [[ADTokenCache alloc] init];
    
    // Populate the cache dictionaries
    NSMutableDictionary* cartmanTokens = [NSMutableDictionary dictionaryWithDictionary:
                                          @{ CacheKey(@"mister_kitty") : CartmanItem(@"mister_kitty", NO) }];
    NSMutableDictionary* tokens= [NSMutableDictionary dictionaryWithDictionary:
                                  @{ CartmanUserid() : cartmanTokens }];
    NSMutableDictionary* idtokens = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ CartmanUserid() : CartmanIdtoken() }];
    NSMutableDictionary* tokenCache = [NSMutableDictionary dictionaryWithDictionary:
                                       @{ @"tokens" : tokens,
                                          @"idtokens" : idtokens }];
    [wrapper setCache:tokenCache];

    ADAuthenticationError* error = nil;
    [wrapper removeItemWithKey:CacheKey(@"mister_kitty") userId:CartmanUserid() error:&error];
    XCTAssertNil(error);
    
    NSMutableDictionary* expected = [NSMutableDictionary dictionaryWithDictionary:
                                     @{ @"tokens" : [NSMutableDictionary new],
                                        @"idtokens" : [NSMutableDictionary new] }];
    
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
    ADTokenCache* wrapper1 = [[ADTokenCache alloc] initWithStorage:storage1];
    
    ADTestSimpleStorage* storage2 = [[ADTestSimpleStorage alloc] init];
    ADTokenCache* wrapper2 = [[ADTokenCache alloc] initWithStorage:storage2];
    
    
    // Make sure we've loaded up the storage but haven't checked for updates
    XCTAssertTrue(storage1->_retrieveStorageCalled);
    XCTAssertFalse(storage1->_retrieveIfUpdatedCalled);
    
    
    // Make sure both wrappers start off showing empty and that they checked for updates
    XCTAssertNil([wrapper1 allItems:&error]);
    XCTAssertNil(error);
    XCTAssertTrue(storage1->_retrieveIfUpdatedCalled);
    XCTAssertNil(storage1->_cache);
    [storage1 resetFlags];
    
    XCTAssertNil([wrapper2 allItems:&error]);
    XCTAssertNil(error);
    XCTAssertTrue(storage2->_retrieveIfUpdatedCalled);
    XCTAssertNil(storage2->_cache);
    [storage2 resetFlags];
    
    ADTokenCacheItem* item1 = ReginaItem(@"popularity", YES);
    // Add an item into wrapper 1
    
    [wrapper1 addOrUpdateItem:item1 error:&error];
    XCTAssertTrue(storage1->_retrieveIfUpdatedCalled);
    XCTAssertNotNil(storage1->_cache);
    
    NSArray* items = nil;
    
    // Make sure the item shows up in allItems
    items = [wrapper1 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    XCTAssertEqualObjects(items[0], item1);
    
    // Make sure the pointers are *not* equal (we want to make sure it's a copy,
    // a reference, just in case something in the item changes)
    XCTAssertNotEqual(items[0], item1);
    [storage1 resetFlags];

    // Copy the data from storage 1 into storage 2 "under the covers"
    [storage2 changeCache:storage1->_cache];
    
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
    [wrapper1 addOrUpdateItem:item1 error:&error];
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

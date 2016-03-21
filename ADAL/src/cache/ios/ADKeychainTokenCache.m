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

#import <Security/Security.h>
#import "ADAL_Internal.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "NSString+ADHelperMethods.h"
#import "ADTokenCacheKey.h"
#import "ADUserInformation.h"
#import "ADWorkplaceJoinUtil.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheItem+Internal.h"

#define KEYCHAIN_VERSION 1
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

static NSString* const s_nilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
static NSString* const s_delimiter = @"|";

static NSString* const s_libraryString = @"MSOpenTech.ADAL." TOSTRING(KEYCHAIN_VERSION);

@implementation ADKeychainTokenCache
{
    NSString* _sharedGroup;
    NSDictionary* _default;
}

// Shouldn't be called.
- (id)init
{
    return [self initWithGroup:[[ADAuthenticationSettings sharedInstance] defaultKeychainGroup]];
}

- (id)initWithGroup:(NSString *)sharedGroup
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!sharedGroup)
    {
        sharedGroup = [[NSBundle mainBundle] bundleIdentifier];
    }
    
    _sharedGroup = [[NSString alloc] initWithFormat:@"%@.%@", [[ADWorkPlaceJoinUtil WorkPlaceJoinUtilManager]  getApplicationIdentifierPrefix], sharedGroup];
    
    _default = @{
                 (id)kSecClass : (id)kSecClassGenericPassword,
                 //Apps are not signed on the simulator, so the shared group doesn't apply there.
#if !(TARGET_IPHONE_SIMULATOR)
                 (id)kSecAttrAccessGroup : (id)_sharedGroup,
#endif
                 (id)kSecAttrGeneric : [s_libraryString dataUsingEncoding:NSUTF8StringEncoding]
                 };
    SAFE_ARC_RETAIN(_default);
    
    return self;
}

-  (NSString*)sharedGroup
{
    return _sharedGroup;
}

#pragma mark -
#pragma mark Keychain Loggig

//Log operations that result in storing or reading cache item:
- (void)logItem:(ADTokenCacheItem *)item
        message:(NSString *)additionalMessage
  correlationId:(NSUUID *)correlationId
{
    [item logMessage:additionalMessage level:ADAL_LOG_LEVEL_VERBOSE correlationId:correlationId];
}

- (void)logItemRetrievalStatus:(NSArray *)items
                           key:(ADTokenCacheKey *)key
                        userId:(NSString *)userId
                 correlationId:(NSUUID *)correlationId
{
    if (!items || [items count]<=0)
    {
        //if resource is nil, this request is intending to find MRRT
        if ([NSString adIsStringNilOrBlank:[key resource]]) {
            AD_LOG_INFO_F(@"No MRRT found", correlationId, @"resource <%@> + client <%@> + authority <%@>", [key resource], [key clientId], [key authority]);
        }
        else
        {
            AD_LOG_INFO_F(@"No AT was found", correlationId, @"resource <%@> + client <%@> + authority <%@>", [key resource], [key clientId], [key authority]);
        }
    }
    else
    {
        NSString* msg = [NSString stringWithFormat:@"Found %lu token(s)", (unsigned long)[items count]];
        AD_LOG_INFO_F(msg, correlationId, @"user <%@>", userId);
    }
}

- (void)logTombstones:(NSArray *)items
{
    for (ADTokenCacheItem* item in items)
    {
        if (item.tombstone)
        {
            [item logMessage:nil level:ADAL_LOG_LEVEL_WARN correlationId:nil];
        }
    }
}

- (NSString*)getTokenNameForLog:(ADTokenCacheItem *)item
{
    NSString* tokenName = @"unknown token";
    if (![NSString adIsStringNilOrBlank:item.accessToken])
    {
        if (item.isExpired)
        {
            tokenName = @"expired AT";
        }
        else
        {
            tokenName = @"AT";
        }
        
        if (![NSString adIsStringNilOrBlank:item.refreshToken])
        {
            [tokenName stringByAppendingString:@"+RT"];
        }
    }
    else if (![NSString adIsStringNilOrBlank:item.refreshToken] && [NSString adIsStringNilOrBlank:item.resource])
    {
        tokenName = @"MRRF";
    }
    return tokenName;
}


// Internal method: returns a dictionary with all items that match the criteria.
// The keys are the keychain fullkey of the items; the values are the
// keychain attributes as extracted by SecItemCopyMatching. The attributes
// (represented as dictionaries) can be used to obtain the actual token cache item.
// May return nil in case of error.
- (NSArray *)keychainItemsWithKey:(ADTokenCacheKey*)key
                           userId:(NSString*)userId
                            error:(ADAuthenticationError* __autoreleasing*)error
{
    NSMutableDictionary* query = [self queryDictionaryForKey:key
                                                  userId:userId
                                              additional:@{ (id)kSecMatchLimit : (id)kSecMatchLimitAll,
                                                            (id)kSecReturnData : @YES,
                                                            (id)kSecReturnAttributes : @YES}];
    NSArray* items = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&items);
    if (status == errSecItemNotFound)
    {
        // We don't want to print an error in this case as it's usually not actually an error.
        AD_LOG_INFO(@"Nothing found in keychain.", nil, nil);
        return @[];
    }
    else if (status != errSecSuccess)
    {
        [ADKeychainTokenCache checkStatus:status operation:@"retrieve items" correlationId:nil error:error];
        return nil;
    }
    
    return items;
}


- (ADTokenCacheItem*)itemFromKeyhainAttributes:(NSDictionary*)attrs
{
    NSData* data = [attrs objectForKey:(id)kSecValueData];
    if (!data)
    {
        AD_LOG_WARN(@"Retrieved item with key that did not have generic item data!", nil, nil);
        return nil;
    }
    
    ADTokenCacheItem* item = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    if (!item)
    {
        AD_LOG_WARN(@"Unable to decode item from data stored in keychain.", nil, nil);
        return nil;
    }
    if (![item isKindOfClass:[ADTokenCacheItem class]])
    {
        AD_LOG_WARN(@"Unarchived Item was not of expected class", nil, nil);
        return nil;
    }
    
    return item;
}

#pragma mark -
#pragma mark ADTokenCacheAccessor implementation

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray* items = [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
    return [self filterOutTombstones:items];
}

/*!
    @param  item    The item to be removed. Item with refresh token will be set as a tombstone, those without will be deleted.
    @param  error   (Optional) In the case of an error this will be filled with the
                    error details.
 
    @return YES if the item was successfully tombstoned/deleted or not in the cache.
 */
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    RETURN_NO_ON_NIL_ARGUMENT(item);
    
    [item logMessage:@"Removing" level:ADAL_LOG_LEVEL_INFO correlationId:nil];

    OSStatus deleteStatus = [self deleteItem:item error:error];
    
    //if item does not exist in cache or does not contain a refresh token, deletion is enough and should return.
    if (deleteStatus != errSecSuccess || [NSString adIsStringNilOrBlank:item.refreshToken])
    {
        return [ADKeychainTokenCache checkStatus:deleteStatus operation:@"delete" correlationId:nil error:error];
    }
    
    [item makeTombstone:@{ @"errorDetails" : @"Manually removed from cache."}];
    //update tombstone in cache
    BOOL updateStatus = [self addOrUpdateItem:item correlationId:nil error:error];
    
    return updateStatus;
    
}

//Interal function: delete an item from keychain;
- (OSStatus)deleteItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    RETURN_NO_ON_NIL_ARGUMENT(item);
    ADTokenCacheKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    NSMutableDictionary* query = [self queryDictionaryForKey:key
                                                      userId:item.userInformation.userId
                                                  additional:nil];
    return SecItemDelete((CFDictionaryRef)query);
}

- (NSMutableArray *)filterOutTombstones:(NSArray *)items
{
    if (!items)
    {
        return nil;
    }
    
    NSMutableArray* itemsKept = [NSMutableArray new];
    for (ADTokenCacheItem* item in items)
    {
        if (![item tombstone])
        {
            [itemsKept addObject:item];
        }
    }
    SAFE_ARC_AUTORELEASE(itemsKept);
    return itemsKept;
}

- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    AD_LOG_WARN_DICT(([NSString stringWithFormat:@"Removing all items for client <%@>", clientId]), nil,
                     (@{ @"operation" : @"removeAllForClientId:", @"clientId" : clientId }), nil);
    
    BOOL deleteSuccessful = YES;
    NSArray* items = [self allItems:nil];
    for (ADTokenCacheItem * item in items)
    {
        if ([clientId isEqualToString:[item clientId] ])
        {
            [self removeItem:item error:error];
            if (*error)
            {
                deleteSuccessful = NO;
            }
        }
    }
    return deleteSuccessful;
}

- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                  clientId:(NSString * __nonnull)clientId
                     error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    AD_LOG_WARN_DICT_F(([NSString stringWithFormat:@"Removing all items for user + client <%@>", clientId]), nil,
                       (@{ @"operation" : @"removeAllForUserId:clientId:", @"clientId" : clientId, @"userId" : userId }),
                       @"userId: %@", userId);
    
    BOOL deleteSuccessful = YES;
    NSArray* items = [self allItems:nil];
    for (ADTokenCacheItem * item in items)
    {
        if ([userId isEqualToString:[[item userInformation] userId]]
            && [clientId isEqualToString:[item clientId]])
        {
            [self removeItem:item error:error];
            if (*error)
            {
                deleteSuccessful = NO;
            }
        }
    }
    return deleteSuccessful;
}

@end

@implementation ADKeychainTokenCache (Internal)

#pragma mark -
#pragma mark Keychain Query Dictionary Utils

//We should not put nil keys in the keychain. The method substitutes nil with a special GUID:
+ (NSString*)getAttributeName:(NSString* )original
{
    return ([NSString adIsStringNilOrBlank:original]) ? s_nilKey : [original adBase64UrlEncode];
}

// Given an item key, generates the string key used in the keychain:
- (NSString*)keychainKeyFromCacheKey:(ADTokenCacheKey *)itemKey
{
    //The key contains all of the ADAL cache key elements plus the version of the
    //library. The latter is required to ensure that SecItemAdd won't break on collisions
    //with items left over from the previous versions of the library.
    return [NSString stringWithFormat:@"%@%@%@%@%@%@%@",
            s_libraryString, s_delimiter,
            [itemKey.authority adBase64UrlEncode], s_delimiter,
            [self.class getAttributeName:itemKey.resource], s_delimiter,
            [itemKey.clientId adBase64UrlEncode]
            ];
}

+ (BOOL)checkStatus:(OSStatus)status
          operation:(NSString *)operation
      correlationId:(NSUUID *)correlationId
              error:(ADAuthenticationError* __autoreleasing *)error
{
    if (status == errSecSuccess || status == errSecItemNotFound)
    {
        return NO;
    }
    
    ADAuthenticationError* adError = [ADAuthenticationError keychainErrorFromOperation:operation status:status correlationId:correlationId];
    if (error)
    {
        *error = adError;
    }
    
    return YES;
}

- (NSMutableDictionary*)queryDictionaryForKey:(ADTokenCacheKey *)key
                                       userId:(NSString *)userId
                                   additional:(NSDictionary*)additional
{
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:_default];
    if (key)
    {
        [query setObject:[self keychainKeyFromCacheKey:key]
                  forKey:(NSString*)kSecAttrService];
    }
    if (userId)
    {
        [query setObject:userId
                  forKey:(NSString*)kSecAttrAccount];
    }
    
    if (additional)
    {
        [query addEntriesFromDictionary:additional];
    }
    
    return query;
}

- (NSArray<ADTokenCacheItem *> *)getItemsWithKey:(ADTokenCacheKey *)key
                                          userId:(NSString *)userId
                                   correlationId:(NSUUID *)correlationId
                                           error:(ADAuthenticationError * __autoreleasing* )error
{
    NSArray* items = [self keychainItemsWithKey:key userId:userId error:error];
    if (!items)
    {
        [self logItemRetrievalStatus:nil key:key userId:userId correlationId:correlationId];
        return nil;
    }
    
    NSMutableArray* tokenItems = [[NSMutableArray<ADTokenCacheItem *> alloc] initWithCapacity:items.count];
    SAFE_ARC_AUTORELEASE(tokenItems);
    for (NSDictionary* attrs in items)
    {
        ADTokenCacheItem* item = [self itemFromKeyhainAttributes:attrs];
        if (!item)
        {
            continue;
        }
        
        [tokenItems addObject:item];
    }
    
    [self logItemRetrievalStatus:tokenItems key:key userId:userId correlationId:correlationId];
    return tokenItems;
    
}

/*!
    @param key      The key of the item.
    @param userId   The specific user whose item is needed. May be nil, in which
                    case the item for the first user in the cache will be returned.
    @param error    Will be set only in case of ambiguity. E.g. if userId is nil
                    and we have tokens from multiple users. If the cache item is not
                    present, the error will not be set.
 */
- (ADTokenCacheItem*)getItemWithKey:(ADTokenCacheKey *)key
                             userId:(NSString *)userId
                      correlationId:(NSUUID *)correlationId
                              error:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray* items = [self getItemsWithKey:key userId:userId correlationId:correlationId error:error];
    NSArray* itemsExcludingTombstones = [self filterOutTombstones:items];
    
    //if nothing but tombstones is found, tombstones details should be logged.
    if (!itemsExcludingTombstones || [itemsExcludingTombstones count]==0)
    {
        [self logTombstones:items];
        return nil;
    }
    
    if (itemsExcludingTombstones.count > 1)
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_MULTIPLE_USERS
                                               protocolCode:nil
                                               errorDetails:@"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used."
                                              correlationId:correlationId];
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    return itemsExcludingTombstones.firstObject;
}

/*!
    Ensures the cache contains an item matching the passed in item, adding or updating the
    item as necessary.
    
    @param  item    The item to add to the cache, or update if an item matching the key and
                    userId already exists in the cache.
    @param  error   (Optional) In the case of an error this will be filled with the
                    error details.
 */
- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
          correlationId:(nullable NSUUID *)correlationId
                  error:(ADAuthenticationError * __autoreleasing*)error
{
    @synchronized(self)
    {
        ADTokenCacheKey* key = [item extractKey:error];
        if (!key)
        {
            return NO;
        }
        
        // In layers above this a nil/blank user ID means we simply don't know who it is (thanks to ADFS)
        // however for the purposes of adding users we still do need to have an account name, even if it
        // is just blank.
        NSString* userId = item.userInformation.userId;
        if (!userId)
        {
            userId = @"";
        }
        
        // If the item wasn't found that means we need to add it.
        NSMutableDictionary* query = [self queryDictionaryForKey:key
                                                          userId:userId
                                                      additional:nil];
        
        NSData* itemData = [NSKeyedArchiver archivedDataWithRootObject:item];
        if (!itemData)
        {
            ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_BAD_FORMAT protocolCode:nil errorDetails:@"Failed to archive keychain item" correlationId:correlationId];
            if (error)
            {
                *error = adError;
            }
            return NO;
        }
        
        NSDictionary* attrToUpdate = @{ (id)kSecValueData : itemData };
        OSStatus status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)attrToUpdate);
        if (status == errSecSuccess)
        {
            return YES;
        }
        else if (status == errSecItemNotFound)
        {
            // If the item wasn't found that means we need to add it instead.
            
            [query addEntriesFromDictionary:@{ (id)kSecValueData : itemData,
                                               (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly}];
            status = SecItemAdd((CFDictionaryRef)query, NULL);
            if ([ADKeychainTokenCache checkStatus:status operation:@"add" correlationId:correlationId error:error])
            {
                return NO;
            }
        }
        else if ([ADKeychainTokenCache checkStatus:status operation:@"update" correlationId:correlationId error:error])
        {
            return NO;
        }
    }
    
    return YES;
}

- (void)testRemoveAll:(ADAuthenticationError * __autoreleasing *)error
{
    AD_LOG_ERROR(@"******** -testRemoveAll: being called in ADKeychainTokenCache. This method should NEVER be called in production code. ********", 0, nil, nil);
    @synchronized(self)
    {
        NSMutableDictionary* query = [self queryDictionaryForKey:nil userId:nil additional:nil];
        OSStatus status = SecItemDelete((CFDictionaryRef)query);
        [ADKeychainTokenCache checkStatus:status operation:@"remove all" correlationId:nil error:error];
    }
}

- (NSDictionary *)defaultKeychainQuery
{
    return _default;
}

- (NSArray<ADTokenCacheItem *> *)allTombstones:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray* items = [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
    NSMutableArray* tombstones = [NSMutableArray new];
    for (ADTokenCacheItem* item in items)
    {
        if ([item tombstone])
        {
            [tombstones addObject:item];
        }
    }
    SAFE_ARC_AUTORELEASE(tombstones);
    return tombstones;
}

@end

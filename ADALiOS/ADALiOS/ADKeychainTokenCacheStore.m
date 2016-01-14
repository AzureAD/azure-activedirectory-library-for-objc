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

#import <Security/Security.h>
#import "ADALiOS.h"
#import "ADKeychainTokenCacheStore.h"
#import "ADTokenCacheStoreItem.h"
#import "NSString+ADHelperMethods.h"
#import "ADTokenCacheStoreKey.h"
#import "ADUserInformation.h"
#import "ADWorkplaceJoinUtil.h"

#define KEYCHAIN_VERSION 1
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

static NSString* const s_nilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
static NSString* const s_delimiter = @"|";

static NSString* const s_libraryString = @"MSOpenTech.ADAL." TOSTRING(KEYCHAIN_VERSION);

static NSString* const sMultiUserError = @"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used.";
static NSString* const sKeychainSharedGroup = @"com.microsoft.adalcache";

@implementation ADKeychainTokenCacheStore
{
    NSString* _sharedGroup;
    NSDictionary* _default;
}

// Shouldn't be called.
- (id)init
{
    return [self initWithGroup:sKeychainSharedGroup];
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
#pragma mark Keychain Query Dictionary Utils

//We should not put nil keys in the keychain. The method substitutes nil with a special GUID:
+ (NSString*)getAttributeName:(NSString* )original
{
    return ([NSString adIsStringNilOrBlank:original]) ? s_nilKey : [original adBase64UrlEncode];
}

// Given an item key, generates the string key used in the keychain:
- (NSString*)keychainKeyFromCacheKey:(ADTokenCacheStoreKey *)itemKey
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

- (NSMutableDictionary*)queryDictionaryForKey:(ADTokenCacheStoreKey *)key
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

#pragma mark -
#pragma mark Keychain Loggig

//Log operations that result in storing or reading cache item:
- (void)logItem:(ADTokenCacheStoreItem *)item
        message:(NSString *)additionalMessage
{
    AD_LOG_VERBOSE_F(@"Keychain token cache store", nil, @"%@ for resource <%@> + client <%@> + authority <%@>", additionalMessage, [item resource], [item clientId], [item authority]);
}

- (void)logItemRetrievalStatus:(NSArray *)items
                           key:(ADTokenCacheStoreKey *)key
                        userId:(NSString *)userId
{
    if ([items count] > 0)
    {
        AD_LOG_VERBOSE_F(@"Keychain token cache store", nil, @"Found %lu token(s) for user <%@> in keychain.", (unsigned long)[items count], userId);
    }
    else
    {
        //if resource is nil, this request is intending to find MRRT
        if ([NSString adIsStringNilOrBlank:[key resource]]) {
            AD_LOG_VERBOSE_F(@"Keychain token cache store", nil, @"No MRRT was found for resource <%@> + client <%@> + authority <%@>", [key resource], [key clientId], [key authority]);
        }
        else
        {
            AD_LOG_VERBOSE_F(@"Keychain token cache store", nil, @"No AT/RT was found for resource <%@> + client <%@> + authority <%@>", [key resource], [key clientId], [key authority]);
        }
    }
}

- (NSString*)getTokenNameForLog:(ADTokenCacheStoreItem *)item
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
- (NSArray *)keychainItemsWithKey:(ADTokenCacheStoreKey*)key
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
        [ADKeychainTokenCacheStore checkStatus:status details:@"Failed to run keychain query." error:error];
        return nil;
    }
    
    return items;
}


- (ADTokenCacheStoreItem*)itemFromKeyhainAttributes:(NSDictionary*)attrs
{
    NSData* data = [attrs objectForKey:(id)kSecValueData];
    if (!data)
    {
        AD_LOG_WARN(@"Retrieved item with key that did not have generic item data!", nil, nil);
        return nil;
    }
    
    ADTokenCacheStoreItem* item = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    if (!item)
    {
        AD_LOG_WARN(@"Unable to decode item from data stored in keychain.", nil, nil);
        return nil;
    }
    if (![item isKindOfClass:[ADTokenCacheStoreItem class]])
    {
        AD_LOG_WARN(@"Unarchived Item was not of expected class", nil, nil);
        return nil;
    }
    
    return item;
}

- (NSArray<ADTokenCacheStoreItem *> *)getItemsWithKey:(ADTokenCacheStoreKey *)key
                                               userId:(NSString *)userId
                                                error:(ADAuthenticationError * __autoreleasing* )error
{
    return [self getItemsWithKey:key userId:userId fromGraveyard:NO error:error];
    
}

//Retrieve normal cache items if "fromGraveyard" is NO;
//Retrieve dead cache items from graveyard if it is YES.
- (NSArray<ADTokenCacheStoreItem *> *)getItemsWithKey:(ADTokenCacheStoreKey *)key
                                               userId:(NSString *)userId
                                        fromGraveyard:(BOOL)fromGraveyard
                                                error:(ADAuthenticationError * __autoreleasing* )error
{
    NSArray* items = [self keychainItemsWithKey:key userId:userId error:error];
    if (!items)
    {
        [self logItemRetrievalStatus:nil key:key userId:userId];
        return nil;
    }
    
    NSMutableArray* tokenItems = [[NSMutableArray<ADTokenCacheStoreItem *> alloc] initWithCapacity:items.count];
    SAFE_ARC_AUTORELEASE(tokenItems);
    for (NSDictionary* attrs in items)
    {
        ADTokenCacheStoreItem* item = [self itemFromKeyhainAttributes:attrs];
        if (item)
        {
            BOOL validity =  fromGraveyard ? [item markAsDead] : ![item markAsDead];
            if (validity)
            {
                [tokenItems addObject:item];
            }
        }
    }
    
    [self logItemRetrievalStatus:tokenItems key:key userId:userId];
    return tokenItems;
    
}

- (NSArray<ADTokenCacheStoreItem *> *)getTombstonedItemsWithKey:(ADTokenCacheStoreKey*)key
                                                         userId:(NSString *)userId
                                                          error:(ADAuthenticationError* __autoreleasing*)error
{
    return [self getItemsWithKey:key userId:userId fromGraveyard:YES error:error];
}

#pragma mark -
#pragma mark ADTokenCacheStoring implementation

/*! Return a copy of all items. The array will contain ADTokenCacheStoreItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheStoreItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:nil error:error];
}

/*! May return nil, if no cache item corresponds to the requested key
 @param key: The key of the item.
 @param user: The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error: Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not present,
 the error will not be set. */
- (ADTokenCacheStoreItem*)getItemWithKey:(ADTokenCacheStoreKey *)key
                                  userId:(NSString *)userId
                                   error:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray* items = [self getItemsWithKey:key userId:userId error:error];
    if (!items || items.count == 0)
    {
        return nil;
    }
    
    if (items.count > 1)
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MULTIPLE_USERS
                                               protocolCode:nil
                                               errorDetails:sMultiUserError];
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    return items.firstObject;
}


/*! Returns all of the items for a given key. Multiple items may present,
 if the same resource was accessed by more than one user. The returned
 array should contain only ADTokenCacheStoreItem objects. Returns an empty array,
 if no items are found. Returns nil (and sets the error parameter) in case of error.*/
- (NSArray<ADTokenCacheStoreItem *> *)getItemsWithKey:(ADTokenCacheStoreKey *)key
                                                error:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:key userId:nil error:error];
}

+ (BOOL)checkStatus:(OSStatus)status
            details:(NSString*)details
              error:(ADAuthenticationError* __autoreleasing *)error
{
    if (status == errSecSuccess || status == errSecItemNotFound)
    {
        return NO;
    }
    
    NSError* nsError = [NSError errorWithDomain:@"Keychain" code:status userInfo:nil];
    ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:nsError errorDetails:details];
    if (error)
    {
        *error = adError;
    }
    
    return YES;
}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error: in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (void)addOrUpdateItem:(ADTokenCacheStoreItem *)item
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    @synchronized(self)
    {
        ADTokenCacheStoreKey* key = [item extractKey:error];
        if (!key)
        {
            return;
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
        
        OSStatus status = SecItemDelete((CFDictionaryRef)query);
        if ([ADKeychainTokenCacheStore checkStatus:status details:@"Failed to remove previous entry from the keychain." error:error])
        {
            return;
        }
        
        NSData* itemData = [NSKeyedArchiver archivedDataWithRootObject:item];
        [query addEntriesFromDictionary:@{ (id)kSecValueData : itemData,
                                           (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly}];
        status = SecItemAdd((CFDictionaryRef)query, NULL);
        
        [ADKeychainTokenCacheStore checkStatus:status details:@"Failed to add or update keychain entry." error:error];
    }
}

/*! Clears token cache details for specific keys.
 @param key: the key of the cache item. Key can be extracted from the ADTokenCacheStoreItem using
 the method 'extractKey'
 @param userId: The user for which the item will be removed. Can be nil, in which case items for all users with
 the specified key will be removed.
 The method does not raise an error, if the item is not found.
 */
- (void)removeItemWithKey:(ADTokenCacheStoreKey *)key
                   userId:(NSString *)userId
                    error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!key)
    {
        ADAuthenticationError* adError = [ADAuthenticationError errorFromArgument:key argumentName:@"key"];
        if (error)
        {
            *error = adError;
        }
        
        return;
    }
    
    NSMutableDictionary* query = [self queryDictionaryForKey:key userId:userId additional:nil];
    OSStatus status = SecItemDelete((CFDictionaryRef)query);
    [ADKeychainTokenCacheStore checkStatus:status details:@"Failed to remove item from keychain" error:error];
}

/*! Mark a cache item as dead instead of removing it.
 @param item: the item being marked as dead. Key will be extracted from the item.
 @param userId: The user for which the item will be removed. Can be nil, in which case items for all users with
 the specified key will be removed.
 @param error: in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (void)tombstoneItem:(ADTokenCacheStoreItem *)item
        requestCorrelationId:(NSString *)requestCorrelationId
                error:(ADAuthenticationError * __autoreleasing *)error
{
    if ([self cacheContainsItem:item])
    {
        ADTokenCacheStoreItem* tombstonedItem = [item copy];
        
        [tombstonedItem setMarkAsDead:YES];
        [tombstonedItem setCorrelationId:requestCorrelationId];
        
        [self addOrUpdateItem:tombstonedItem error:error];
        [tombstonedItem release];
    }
}

- (BOOL)cacheContainsItem:(ADTokenCacheStoreItem *)item
{
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKey:&error];
    
    ADTokenCacheStoreItem* read = nil;
    if (item.userInformation)
    {
        read = [self getItemWithKey:key userId:item.userInformation.userId error:&error];
    }
    else
    {
        //Find the one (if any) that has userId equal to nil:
        NSArray* all = [self getItemsWithKey:key error:&error];
        for(ADTokenCacheStoreItem* i in all)
        {
            if (!i.userInformation)
            {
                read = i;
                break;
            }
        }
    }

    if (read)
    {
        return YES;
    }
    else
    {
        return NO;
    }
}

@end

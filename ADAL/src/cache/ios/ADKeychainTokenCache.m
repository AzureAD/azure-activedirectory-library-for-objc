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
#import "ADKeychainUtil.h"
#import "ADTokenCacheItem.h"
#import "NSString+ADHelperMethods.h"
#import "ADTokenCacheKey.h"
#import "ADUserInformation.h"
#import "ADWorkplaceJoinUtil.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADHelpers.h"

#define KEYCHAIN_VERSION 1
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define ONE_DAY_IN_SECONDS (24*60*60)

static NSString* const s_nilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
static NSString* const s_delimiter = @"|";

static NSString* const s_libraryString = @"MSOpenTech.ADAL." TOSTRING(KEYCHAIN_VERSION);

static NSString* const s_wipeLibraryString = @"Microsoft.ADAL.WipeAll." TOSTRING(KEYCHAIN_VERSION);

static NSString* s_defaultKeychainGroup = @"com.microsoft.adalcache";
static ADKeychainTokenCache* s_defaultCache = nil;

@implementation ADKeychainTokenCache
{
    NSString* _sharedGroup;
    NSDictionary* _default;
}

+ (ADKeychainTokenCache*)defaultKeychainCache
{
    static dispatch_once_t s_once;
    
    dispatch_once(&s_once, ^{
        s_defaultCache = [[ADKeychainTokenCache alloc] init];
    });
    
    
    return s_defaultCache;
}

+ (ADKeychainTokenCache*)keychainCacheForGroup:(nullable NSString*)group
{
    if ([group isEqualToString:s_defaultKeychainGroup])
    {
        return [self defaultKeychainCache];
    }
    ADKeychainTokenCache* cache = [[ADKeychainTokenCache alloc] initWithGroup:group];
    return cache;
}

+ (NSString*)defaultKeychainGroup
{
    return s_defaultKeychainGroup;
}

+ (void)setDefaultKeychainGroup:(NSString *)keychainGroup
{
    if (s_defaultCache)
    {
        AD_LOG_ERROR(nil, @"Failed to set default keychain group, default keychain cache has already been instantiated.");
        
        @throw @"Attempting to change the keychain group once AuthenticationContexts have been created or the default keychain cache has been retrieved is invalid. The default keychain group should only be set once for the lifetime of an application.";
    }
    
    AD_LOG_INFO_PII(nil, @"Setting default keychain group.");
    AD_LOG_INFO_PII(nil, @"Setting default keychain group to %@", keychainGroup);
    
    if (keychainGroup == s_defaultKeychainGroup)
    {
        return;
    }
    
    if (!keychainGroup)
    {
        keychainGroup = [[NSBundle mainBundle] bundleIdentifier];
    }
    
    s_defaultKeychainGroup = [keychainGroup copy];
}

// Shouldn't be called.
- (id)init
{
    return [self initWithGroup:s_defaultKeychainGroup];
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
    
    NSString* teamId = [ADKeychainUtil keychainTeamId:nil];
#if !TARGET_OS_SIMULATOR
    // If we didn't find a team ID and we're on device then the rest of ADAL not only will not work
    // particularly well, we'll probably induce other issues by continuing.
    if (!teamId)
    {
        return nil;
    }
#endif
    if (teamId)
    {
        _sharedGroup = [[NSString alloc] initWithFormat:@"%@.%@", teamId, sharedGroup];
    }
    
    NSMutableDictionary* defaultQuery =
    [@{
       (id)kSecClass : (id)kSecClassGenericPassword,
       (id)kSecAttrGeneric : [s_libraryString dataUsingEncoding:NSUTF8StringEncoding]
       } mutableCopy];

    // Depending on the environment we may or may not have keychain access groups. Which environments
    // have keychain access group support also varies over time. They should always work on device,
    // in Simulator they work when running within an app bundle but not in unit tests, as of Xcode 7.3
    
    if (_sharedGroup)
    {
        [defaultQuery setObject:_sharedGroup forKey:(id)kSecAttrAccessGroup];
    }
    
    _default = defaultQuery;
    
    return self;
}

-  (NSString*)sharedGroup
{
    return _sharedGroup;
}


#pragma mark -
#pragma mark Token Wipe
- (NSMutableDictionary *)wipeQuery {
    static NSDictionary *sWipeQuery;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sWipeQuery = @{
                       (id)kSecClass                : (id)kSecClassGenericPassword,
                       (id)kSecAttrGeneric          : [s_wipeLibraryString dataUsingEncoding:NSUTF8StringEncoding],
                       (id)kSecAttrAccessGroup      : _sharedGroup,
                       (id)kSecAttrAccount          : @"TokenWipe",
                       };
    });
    return [sWipeQuery mutableCopy];
}

- (BOOL)saveWipeTokenData:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    NSMutableDictionary *query = [self wipeQuery];
    
    NSDictionary *wipeInfo = @{ @"bundleId" : [[NSBundle mainBundle] bundleIdentifier],
                                @"wipeTime" : [NSDate date]
                                };

    NSData *wipeData = [NSKeyedArchiver archivedDataWithRootObject:wipeInfo];

    OSStatus status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)@{ (id)kSecValueData:wipeData  } );
    if (status == errSecItemNotFound)
    {
        [query addEntriesFromDictionary: @{ (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                            (id)kSecValueData : wipeData
                                            }];
         
        status = SecItemAdd((CFDictionaryRef)query, NULL);
    }
    
    if(status != errSecSuccess)
    {
        NSString* details = [NSString stringWithFormat:@"Failed to log wipe data with error: %d", (int)status];
        NSError* nserror = [NSError errorWithDomain:@"Could not log wipe data."
                                               code:AD_ERROR_UNEXPECTED
                                           userInfo:nil];
        if (error)
        {
            *error = [ADAuthenticationError errorFromNSError:nserror
                                                errorDetails:details
                                               correlationId:nil];
        }
        return NO;
    }
    
    return YES;
}

- (void)logWipeTokenData:(NSUUID *)correlationId
{
    static NSDictionary *sQuery;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableDictionary *query = [self wipeQuery];
        [query setObject:@(YES) forKey:(id)kSecReturnData];
        sQuery = query;
    });
    
    CFTypeRef data = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)sQuery, &data);
    
    if (status == errSecSuccess && data)
    {
        NSDictionary *wipeData = [NSKeyedUnarchiver unarchiveObjectWithData:(__bridge NSData * _Nonnull)(data)];
        CFRelease(data);
        
        NSString *bundleId = wipeData[@"bundleId"];
        NSDate *wipeTime = wipeData[@"wipeTime"];
        
        AD_LOG_INFO(correlationId, @"Last wiped by %@ at %@", bundleId, [ADHelpers stringFromDate:wipeTime]);
        AD_LOG_INFO_PII(correlationId, @"Last wiped by %@ at %@", bundleId, [ADHelpers stringFromDate:wipeTime]);
    }
    else
    {
        AD_LOG_INFO(correlationId, @"Failed to get a wipe data or it does not exist");
        AD_LOG_INFO_PII(correlationId, @"Failed to get a wipe data or it does not exist for %@", _sharedGroup);
    }
    
    return;
}


#pragma mark -
#pragma mark Keychain Logging

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
    NSString* keyCtxStr = [NSString stringWithFormat:@"(resource <%@> + client <%@> + authority <%@>)", [key resource], [key clientId], [key authority]];
    if (!items || [items count]<=0)
    {
        //if resource is nil, this request is intending to find MRRT
        AD_LOG_INFO(correlationId, @"No items were found for query");
        AD_LOG_INFO_PII(correlationId, @"No items were found for query %@", keyCtxStr);
    }
    else
    {
        AD_LOG_INFO(correlationId, @"Found %lu token(s) for query", (unsigned long)[items count]);
        AD_LOG_INFO_PII(correlationId, @"Found %lu token(s) for query %@ user <%@>", (unsigned long)[items count], keyCtxStr, userId);
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
    else if ([item.clientId hasPrefix:@"foci-"])
    {
        tokenName = @"FRT";
    }
    else if (![NSString adIsStringNilOrBlank:item.refreshToken] && [NSString adIsStringNilOrBlank:item.resource])
    {
        tokenName = @"MRRT";
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
    CFTypeRef items = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &items);
    if (status == errSecItemNotFound)
    {
        return @[];
    }
    else if (status != errSecSuccess)
    {
        [ADKeychainTokenCache checkStatus:status operation:@"retrieve items" correlationId:nil error:error];
        return nil;
    }
    
    return CFBridgingRelease(items);
}


- (ADTokenCacheItem*)itemFromKeychainAttributes:(NSDictionary*)attrs
{
    NSData* data = [attrs objectForKey:(id)kSecValueData];
    if (!data)
    {
        AD_LOG_WARN(nil, @"Retrieved item with key that did not have generic item data!");
        return nil;
    }
    @try
    {
        ADTokenCacheItem* item = [NSKeyedUnarchiver unarchiveObjectWithData:data];
        if (!item)
        {
            AD_LOG_WARN(nil, @"Unable to decode item from data stored in keychain.");
            return nil;
        }
        if (![item isKindOfClass:[ADTokenCacheItem class]])
        {
            AD_LOG_WARN(nil, @"Unarchived Item was not of expected class.");
            return nil;
        }
        
        return item;
    }
    @catch (NSException *exception)
    {
        AD_LOG_WARN(nil, @"Failed to deserialize data from keychain.");
        return nil;
    }
}

#pragma mark -
#pragma mark ADTokenCacheAccessor implementation

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
}

/*!
    @param  item    The item to be removed.
    @param  error   (Optional) In the case of an error this will be filled with the
                    error details.
 
    @return YES if the item was successfully deleted or not in the cache, and the wipe data
                   is stored successfully.
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

    return [self saveWipeTokenData:error];
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

- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    AD_LOG_WARN(nil, @"Removing all items for client %@", clientId);
    
    NSArray* items = [self allItems:error];
    if (!items)
    {
        return NO;
    }
    
    for (ADTokenCacheItem * item in items)
    {
        if ([clientId isEqualToString:[item clientId]]
            && ![self removeItem:item error:error])
        {
            return NO;
        }
    }
    return YES;
}

- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                  clientId:(NSString * __nonnull)clientId
                     error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    AD_LOG_WARN(nil, @"Removing all items for user");
    AD_LOG_WARN_PII(nil, @"Removing all items for user + client <%@> userid <%@>", clientId, userId);
    
    NSArray* items = [self allItems:nil];
    if (!items)
    {
        return NO;
    }
    
    for (ADTokenCacheItem * item in items)
    {
        if ([userId isEqualToString:[[item userInformation] userId]]
            && [clientId isEqualToString:[item clientId]]
            && ![self removeItem:item error:error])
        {
            return NO;
        }
    }
    return YES;
}

- (BOOL)wipeAllItemsForUserId:(NSString *)userId error:(ADAuthenticationError *__autoreleasing  _Nullable *)error
{
    AD_LOG_WARN(nil, @"Removing all items for user.");
    AD_LOG_WARN_PII(nil, @"Removing all items for userId <%@>", userId);

    NSDictionary *query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecAttrAccount: [userId adBase64UrlEncode],
                             (id)kSecAttrAccessGroup: _sharedGroup };
    
    OSStatus status = SecItemDelete((CFDictionaryRef)query);
    
    if (![ADKeychainTokenCache checkStatus:status operation:@"remove user" correlationId:nil error:error])
    {
        return NO;
    }
    
    status = [self saveWipeTokenData:error];
    return ![ADKeychainTokenCache checkStatus:status operation:@"saving wipe data" correlationId:nil error:error];
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
        [query setObject:[userId adBase64UrlEncode]
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
    
    if (!items || items.count == 0)
    {
        [self logWipeTokenData:correlationId];
    }
    
    if (!items)
    {
        [self logItemRetrievalStatus:nil key:key userId:userId correlationId:correlationId];
        return nil;
    }
    
    NSMutableArray* tokenItems = [[NSMutableArray<ADTokenCacheItem *> alloc] initWithCapacity:items.count];
    for (NSDictionary* attrs in items)
    {
        ADTokenCacheItem* item = [self itemFromKeychainAttributes:attrs];
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
    
    //if nothing is found, last wipe details should be logged.
    if (!items || items.count == 0)
    {
        [self logWipeTokenData:correlationId];
        return nil;
    }
    
    if (items.count > 1)
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_MULTIPLE_USERS
                                               protocolCode:nil
                                               errorDetails:@"The token cache store for this resource contains more than one user. Please set the 'userId' parameter to the one that will be used."
                                              correlationId:correlationId];
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    return items.firstObject;
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
    AD_LOG_ERROR(nil, @"******** -testRemoveAll: being called in ADKeychainTokenCache. This method should NEVER be called in production code. ********");
    @synchronized(self)
    {
        NSMutableDictionary* query = [self queryDictionaryForKey:nil userId:nil additional:nil];
        OSStatus status = SecItemDelete((CFDictionaryRef)query);
        [ADKeychainTokenCache checkStatus:status operation:@"remove all" correlationId:nil error:error];
        
        //JASON
        query =
        [@{
           (id)kSecClass                : (id)kSecClassGenericPassword,
           (id)kSecAttrGeneric          : [s_wipeLibraryString dataUsingEncoding:NSUTF8StringEncoding],
           (id)kSecAttrAccessGroup      : _sharedGroup,
           (id)kSecAttrAccount          : @"TokenWipe",
           (id)kSecReturnData           : @YES
           } mutableCopy];
        
        status = SecItemDelete((CFDictionaryRef)query);
        [ADKeychainTokenCache checkStatus:status operation:@"remove all" correlationId:nil error:error];
        

    }
}

- (NSDictionary *)defaultKeychainQuery
{
    return _default;
}

@end

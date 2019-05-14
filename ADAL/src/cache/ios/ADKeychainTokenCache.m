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
#import "ADAuthenticationErrorConverter.h"
#import "ADMSIDDataSourceWrapper.h"
#import "MSIDKeychainTokenCache.h"
#import "MSIDKeyedArchiverSerializer.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "ADHelpers.h"

@interface ADKeychainTokenCache()

@property (nonatomic) MSIDKeychainTokenCache *keychainTokenCache;
@property (nonatomic) ADMSIDDataSourceWrapper *msidDataSourceWrapper;

@end

static ADKeychainTokenCache* s_defaultCache = nil;

@implementation ADKeychainTokenCache

#pragma mark - Public shared group

+ (NSString *)defaultKeychainGroup
{
    return MSIDKeychainTokenCache.defaultKeychainGroup;
}

+ (void)setDefaultKeychainGroup:(NSString *)keychainGroup
{
    MSIDKeychainTokenCache.defaultKeychainGroup = keychainGroup;
}

+ (ADKeychainTokenCache *)defaultKeychainCache
{
    static dispatch_once_t s_once;
    
    dispatch_once(&s_once, ^{
        s_defaultCache = [[ADKeychainTokenCache alloc] init];
    });
    
    
    return s_defaultCache;
}

+ (ADKeychainTokenCache *)keychainCacheForGroup:(NSString *)group
{
    if ([group isEqualToString:self.defaultKeychainGroup])
    {
        return [self defaultKeychainCache];
    }
    ADKeychainTokenCache *cache = [[ADKeychainTokenCache alloc] initWithGroup:group];
    return cache;
}

// Shouldn't be called.
- (id)init
{
    return [self initWithGroup:MSIDKeychainTokenCache.defaultKeychainGroup];
}

- (id)initWithGroup:(NSString *)sharedGroup
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _keychainTokenCache = [[MSIDKeychainTokenCache alloc] initWithGroup:sharedGroup];
    _msidDataSourceWrapper = [[ADMSIDDataSourceWrapper alloc] initWithMSIDDataSource:_keychainTokenCache
                                                                          serializer:[MSIDKeyedArchiverSerializer new]];
    
    return self;
}

-  (NSString *)sharedGroup
{
    return _keychainTokenCache.keychainGroup;
}

#pragma mark - Public cache

- (BOOL)removeAllForClientId:(NSString *)clientId
                       error:(ADAuthenticationError **)error
{
    clientId = [clientId msidTrimmedString];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:clientId], clientId, NO);
    
    return [self.msidDataSourceWrapper removeAllForClientId:clientId error:error];
}


- (BOOL)removeAllForUserId:(NSString *)userId
                  clientId:(NSString *)clientId
                     error:(ADAuthenticationError **)error
{
    userId = [ADHelpers normalizeUserId:userId];
    clientId = [clientId msidTrimmedString];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:userId], userId, NO);
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:clientId], clientId, NO);
    
    return [self.msidDataSourceWrapper removeAllForUserId:userId
                                                 clientId:clientId
                                                    error:error];
}

- (BOOL)wipeAllItemsForUserId:(NSString *)userId
                        error:(ADAuthenticationError **)error
{
    userId = [ADHelpers normalizeUserId:userId];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:userId], userId, NO);
    
    return [self.msidDataSourceWrapper wipeAllItemsForUserId:userId error:error];
}

- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError **)error
{
    return [self.msidDataSourceWrapper allItems:error];
}

- (BOOL)removeItem:(ADTokenCacheItem *)item
             error:(ADAuthenticationError **)error
{
    return [self.msidDataSourceWrapper removeItem:item error:error];
}

@end

@implementation ADKeychainTokenCache (Internal)

/*
 TODO: this code will be removed once integration with MSID core is completed.
 It's just necessary to keep all other code and tests from breaking and to do changes in small PRs
 */

- (NSArray<ADTokenCacheItem *> *)getItemsWithKey:(ADTokenCacheKey *)key
                                          userId:(NSString *)userId
                                   correlationId:(NSUUID *)correlationId
                                           error:(ADAuthenticationError * __autoreleasing* )error
{
    return [self.msidDataSourceWrapper getItemsWithKey:key userId:userId correlationId:correlationId error:error];
    
}

- (ADTokenCacheItem*)getItemWithKey:(ADTokenCacheKey *)key
                             userId:(NSString *)userId
                      correlationId:(NSUUID *)correlationId
                              error:(ADAuthenticationError * __autoreleasing *)error
{
    return [self.msidDataSourceWrapper getItemWithKey:key userId:userId correlationId:correlationId error:error];
}

- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
          correlationId:(nullable NSUUID *)correlationId
                  error:(ADAuthenticationError * __autoreleasing*)error
{
    return [self.msidDataSourceWrapper addOrUpdateItem:item correlationId:correlationId error:error];
}

- (NSDictionary *)getWipeTokenData
{
    return [self.msidDataSourceWrapper getWipeTokenData];
}

- (void)testRemoveAll:(ADAuthenticationError **)error
{
    NSError *cacheError = nil;
    [self.keychainTokenCache clearWithContext:nil error:&cacheError];
    
    if (cacheError && error)
    {
        *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
    }
}

@end

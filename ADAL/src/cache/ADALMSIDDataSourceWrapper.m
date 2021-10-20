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

#import "ADALMSIDDataSourceWrapper.h"
#import "MSIDTokenCacheDataSource.h"
#import "MSIDCredentialItemSerializer.h"
#import "ADALAuthenticationErrorConverter.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "ADALTokenCacheItem+MSIDTokens.h"
#import "ADALTokenCacheKey.h"
#import "ADALTokenCacheDataSource.h"
#import "ADALMSIDContext.h"
#import "ADALHelpers.h"
#import "ADALUserInformation.h"
#import "MSIDLegacyTokenCacheQuery.h"
#import "MSIDLegacyTokenCacheItem.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDDefaultTokenCacheAccessor.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDAccountIdentifier.h"

@interface ADALMSIDDataSourceWrapper()

@property (nonatomic) id<MSIDTokenCacheDataSource> dataSource;
@property (nonatomic) id<MSIDCredentialItemSerializer> seriazer;
@property (nonatomic) MSIDLegacyTokenCacheAccessor *legacyAccessor;

@end

@implementation ADALMSIDDataSourceWrapper

#pragma mark - Init

- (instancetype)initWithMSIDDataSource:(id<MSIDTokenCacheDataSource>)dataSource
                            serializer:(id<MSIDCredentialItemSerializer>)serializer
{
    self = [super init];
    
    if (self)
    {
        self.dataSource = dataSource;
        self.seriazer = serializer;

        MSIDOauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
#if TARGET_OS_IPHONE
        MSIDDefaultTokenCacheAccessor *defaultAccessor = [[MSIDDefaultTokenCacheAccessor alloc] initWithDataSource:self.dataSource otherCacheAccessors:nil factory:factory];
        self.legacyAccessor = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:self.dataSource otherCacheAccessors:@[defaultAccessor] factory:factory];
#else
        self.legacyAccessor = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:self.dataSource otherCacheAccessors:nil factory:factory];
#endif
    }
    
    return self;
}

#pragma mark - Accessors

/*! Clears token cache details for specific keys.
 @param item The item to remove from the array.
 */
- (BOOL)removeItem:(ADALTokenCacheItem *)item
             error:(ADALAuthenticationError **)error
{
    NSError *cacheError = nil;
    
    BOOL result = [self.dataSource removeItemsWithKey:[item tokenCacheKey] context:nil error:&cacheError];
    
    if (cacheError && error)
    {
        *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
    }
    
    return result;
}

/*! Return a copy of all items. The array will contain ADALTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADALTokenCacheItem *> *)allItems:(ADALAuthenticationError * __autoreleasing *)error
{
    MSIDLegacyTokenCacheQuery *query = [MSIDLegacyTokenCacheQuery new];
    
    NSError *cacheError = nil;
    
    NSArray *allItems = [self.dataSource tokensWithKey:query
                                            serializer:self.seriazer
                                               context:nil
                                                 error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    if (!allItems)
    {
        return nil;
    }
    
    NSMutableArray<ADALTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDLegacyTokenCacheItem *cacheItem in allItems)
    {
        ADALTokenCacheItem *item = [[ADALTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

- (BOOL)addOrUpdateItem:(ADALTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADALAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *key = [item tokenCacheKey];
    MSIDLegacyTokenCacheItem *tokenCacheItem = [item tokenCacheItem];
    
    NSError *cacheError = nil;
    
    ADALMSIDContext *context = [[ADALMSIDContext alloc] initWithCorrelationId:correlationId];
    
    BOOL result = [self.dataSource saveToken:tokenCacheItem
                                         key:key
                                  serializer:self.seriazer
                                     context:context
                                       error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
        return NO;
    }
    
    return result;
}

#pragma mark - ADALTokenCacheDataSource

/*
 TODO: this code will be removed once integration with MSID core is completed.
 It's just necessary to keep all other code and tests from breaking and to do changes in small PRs
 */

- (ADALTokenCacheItem *)getItemWithKey:(ADALTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(ADALAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *msidKey = [[MSIDLegacyTokenCacheKey alloc] initWithAuthority:[NSURL URLWithString:key.authority]
                                                                                 clientId:key.clientId
                                                                                 resource:key.resource
                                                                             legacyUserId:userId];
    
    NSError *cacheError = nil;
    
    ADALMSIDContext *context = [[ADALMSIDContext alloc] initWithCorrelationId:correlationId];
    
    MSIDCredentialCacheItem *cacheItem = [self.dataSource tokenWithKey:msidKey
                                                            serializer:self.seriazer
                                                               context:context
                                                                 error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    return [[ADALTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:(MSIDLegacyTokenCacheItem *)cacheItem];
}

- (NSArray <ADALTokenCacheItem *> *)getItemsWithKey:(ADALTokenCacheKey *)key
                                           userId:(NSString *)userId
                                    correlationId:(NSUUID * )correlationId
                                            error:(ADALAuthenticationError **)error
{
    MSIDLegacyTokenCacheQuery *query = [MSIDLegacyTokenCacheQuery new];
    query.authority = [NSURL URLWithString:key.authority];
    query.clientId = key.clientId;
    query.resource = key.resource;
    query.legacyUserId = userId;

    NSError *cacheError = nil;
    
    ADALMSIDContext *context = [[ADALMSIDContext alloc] initWithCorrelationId:correlationId];
    
    NSArray *cacheItems = [self.dataSource tokensWithKey:query
                                              serializer:self.seriazer
                                                 context:context
                                                error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    NSMutableArray<ADALTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDLegacyTokenCacheItem *cacheItem in cacheItems)
    {
        ADALTokenCacheItem *item = [[ADALTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

- (BOOL)removeAllForClientId:(NSString *)clientId
                       error:(ADALAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for client");
    MSID_LOG_WARN_PII(nil, @"Removing all items for client %@", clientId);
    
    return [self removeAllForUserIdImpl:nil clientId:clientId error:error];
}


- (BOOL)removeAllForUserId:(NSString *)userId
                  clientId:(NSString *)clientId
                     error:(ADALAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for user");
    MSID_LOG_WARN_PII(nil, @"Removing all items for user + client <%@> userid <%@>", clientId, userId);
    
    return [self removeAllForUserIdImpl:userId clientId:clientId error:error];
}

- (BOOL)wipeAllItemsForUserId:(NSString *)userId
                        error:(ADALAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for user.");
    MSID_LOG_WARN_PII(nil, @"Removing all items for userId <%@>", userId);
    
    return [self removeAllForUserIdImpl:userId clientId:nil error:error];
}

- (BOOL)removeAllForUserIdImpl:(NSString *)userId
                      clientId:(NSString *)clientId
                         error:(ADALAuthenticationError **)error
{
    MSIDAccountIdentifier *account = [[MSIDAccountIdentifier alloc] initWithLegacyAccountId:userId homeAccountId:nil];

    NSError *msidError = nil;
    BOOL result = [_legacyAccessor clearCacheForAccount:account
                                               clientId:clientId
                                                context:nil
                                                  error:&msidError];

    if (!result && error)
    {
        *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:msidError];
    }

    return result;
}

- (NSDictionary *)getWipeTokenData
{
    return [self.dataSource wipeInfo:nil error:nil];
}

@end

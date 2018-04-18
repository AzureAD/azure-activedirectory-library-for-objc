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

#import "ADMSIDDataSourceWrapper.h"
#import "MSIDTokenCacheDataSource.h"
#import "MSIDTokenItemSerializer.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "ADTokenCacheItem+MSIDTokens.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheDataSource.h"
#import "ADMSIDContext.h"
#import "ADHelpers.h"
#import "ADUserInformation.h"

@interface ADMSIDDataSourceWrapper()

@property (nonatomic) id<MSIDTokenCacheDataSource> dataSource;
@property (nonatomic) id<MSIDTokenItemSerializer> seriazer;

@end

@implementation ADMSIDDataSourceWrapper

#pragma mark - Init

- (instancetype)initWithMSIDDataSource:(id<MSIDTokenCacheDataSource>)dataSource
                            serializer:(id<MSIDTokenItemSerializer>)serializer
{
    self = [super init];
    
    if (self)
    {
        self.dataSource = dataSource;
        self.seriazer = serializer;
    }
    
    return self;
}

#pragma mark - Accessors

/*! Clears token cache details for specific keys.
 @param item The item to remove from the array.
 */
- (BOOL)removeItem:(ADTokenCacheItem *)item
             error:(ADAuthenticationError **)error
{
    NSError *cacheError = nil;
    
    BOOL result = [self.dataSource removeItemsWithKey:[item tokenCacheKey] context:nil error:&cacheError];
    
    if (cacheError && error)
    {
        *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
    }
    
    return result;
}

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    MSIDTokenCacheKey *key = [MSIDTokenCacheKey queryForAllItems];
    
    NSError *cacheError = nil;
    
    NSArray<MSIDTokenCacheItem *> *allItems = [self.dataSource tokensWithKey:key
                                                                  serializer:self.seriazer
                                                                     context:nil
                                                                       error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    if (!allItems)
    {
        return nil;
    }
    
    NSMutableArray<ADTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDTokenCacheItem *cacheItem in allItems)
    {
        ADTokenCacheItem *item = [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADAuthenticationError **)error
{
    MSIDTokenCacheKey *key = [item tokenCacheKey];
    MSIDTokenCacheItem *tokenCacheItem = [item tokenCacheItem];
    
    NSError *cacheError = nil;
    
    ADMSIDContext *context = [[ADMSIDContext alloc] initWithCorrelationId:correlationId];
    
    BOOL result = [self.dataSource saveToken:tokenCacheItem
                                         key:key
                                  serializer:self.seriazer
                                     context:context
                                       error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return NO;
    }
    
    return result;
}

#pragma mark - ADTokenCacheDataSource

/*
 TODO: this code will be removed once integration with MSID core is completed.
 It's just necessary to keep all other code and tests from breaking and to do changes in small PRs
 */

- (ADTokenCacheItem *)getItemWithKey:(ADTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(ADAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *msidKey = [MSIDLegacyTokenCacheKey keyWithAuthority:[NSURL URLWithString:key.authority]
                                                                        clientId:key.clientId
                                                                        resource:key.resource
                                                                    legacyUserId:userId];
    
    NSError *cacheError = nil;
    
    ADMSIDContext *context = [[ADMSIDContext alloc] initWithCorrelationId:correlationId];
    
    MSIDTokenCacheItem *cacheItem = [self.dataSource tokenWithKey:msidKey
                                                       serializer:self.seriazer
                                                          context:context
                                                            error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    return [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
}

- (NSArray <ADTokenCacheItem *> *)getItemsWithKey:(ADTokenCacheKey *)key
                                           userId:(NSString *)userId
                                    correlationId:(NSUUID * )correlationId
                                            error:(ADAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *msidKey = [MSIDLegacyTokenCacheKey keyWithAuthority:[NSURL URLWithString:key.authority]
                                                                        clientId:key.clientId
                                                                        resource:key.resource
                                                                    legacyUserId:userId];
    
    NSError *cacheError = nil;
    
    ADMSIDContext *context = [[ADMSIDContext alloc] initWithCorrelationId:correlationId];
    
    NSArray *cacheItems = [self.dataSource tokensWithKey:msidKey
                                              serializer:self.seriazer
                                                 context:context
                                                error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    NSMutableArray<ADTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDTokenCacheItem *cacheItem in cacheItems)
    {
        ADTokenCacheItem *item = [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

- (BOOL)removeAllForClientId:(NSString *)clientId
                       error:(ADAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for client");
    MSID_LOG_WARN_PII(nil, @"Removing all items for client %@", clientId);
    
    return [self removeAllForUserIdImpl:nil clientId:clientId error:error];
}


- (BOOL)removeAllForUserId:(NSString *)userId
                  clientId:(NSString *)clientId
                     error:(ADAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for user");
    MSID_LOG_WARN_PII(nil, @"Removing all items for user + client <%@> userid <%@>", clientId, userId);
    
    return [self removeAllForUserIdImpl:userId clientId:clientId error:error];
}

- (BOOL)wipeAllItemsForUserId:(NSString *)userId
                        error:(ADAuthenticationError **)error
{
    MSID_LOG_WARN(nil, @"Removing all items for user.");
    MSID_LOG_WARN_PII(nil, @"Removing all items for userId <%@>", userId);
    
    BOOL result = [self removeAllForUserIdImpl:userId clientId:nil error:error];
    
    if (result)
    {
        [self.dataSource saveWipeInfoWithContext:nil error:nil];
    }
    
    return result;
}

- (BOOL)removeAllForUserIdImpl:(NSString *)userId
                      clientId:(NSString *)clientId
                         error:(ADAuthenticationError **)error
{
    NSArray *items = [self allItems:nil];
    
    if (!items)
    {
        return NO;
    }
    
    for (ADTokenCacheItem *item in items)
    {
        if ((!userId || [userId isEqualToString:[[item userInformation] userId]])
            && (!clientId || [clientId isEqualToString:[item clientId]])
            && ![self removeItem:item error:error])
        {
            return NO;
        }
    }
    
    return YES;
}

- (NSDictionary *)getWipeTokenData
{
    return [self.dataSource wipeInfo:nil error:nil];
}

@end

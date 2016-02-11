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

#import "ADAuthenticationContext+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADTokenCacheKey.h"
#import "ADUserInformation.h"

@implementation ADAuthenticationContext (TokenCaching)

//Gets an item from the cache, where userId may be nil. Raises error, if items for multiple users
//are present and user id is not specified.
- (ADTokenCacheItem*)extractCacheItemWithKey:(ADTokenCacheKey*)key
                                      userId:(ADUserIdentifier*)userId
                                       error:(ADAuthenticationError* __autoreleasing*)error
{
    if (!key || !self.tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    
    ADAuthenticationError* localError = nil;
    ADTokenCacheItem* item = [self.tokenCacheStore getItemWithKey:key userId:userId.userId error:&localError];
    if (!item && !localError && userId)
    {
        //ADFS fix, where the userId is not received by the server, but can be passed to the API:
        //We didn't find element with the userId, try finding an item with a blank userId:
        item = [self.tokenCacheStore getItemWithKey:key userId:@"" error:&localError];
    }
    if (error && localError)
    {
        *error = localError;
    }
    return item;
}

//Checks the cache for item that can be used to get directly or indirectly an access token.
//Checks the multi-resource refresh tokens too.
- (ADTokenCacheItem *)findCacheItemWithKey:(ADTokenCacheKey *) key
                                    userId:(ADUserIdentifier *)userId
                                     error:(ADAuthenticationError * __autoreleasing *)error
{
    if (error)
    {
        *error = nil;
    }
    
    if (!key || !self.tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    ADAuthenticationError* localError = nil;
    ADTokenCacheItem* item = [self extractCacheItemWithKey:key userId:userId error:&localError];
    if (localError)
    {
        if (error)
        {
            *error = localError;
        }
        return nil;
    }
    
    if (item.accessToken && !item.isExpired)
    {
        return item;
    }
    
    if (![NSString adIsStringNilOrBlank:item.refreshToken])
    {
        // Suitable direct refresh token found.
        return item;
    }
    
    // We have a cache item that cannot be used anymore, remove it from the cache:
    [self.tokenCacheStore removeItem:item error:nil];
    
    if (![NSString adIsStringNilOrBlank:key.resource])
    {
        //The request came for specific resource. Try returning a multi-resource refresh token:
        ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:self.authority
                                                                       resource:nil
                                                                       clientId:key.clientId
                                                                          error:&localError];
        if (!broadKey)
        {
            AD_LOG_WARN(@"Unexpected error", [self correlationId], localError.errorDetails);
            return nil;//Recover
        }
        ADTokenCacheItem* broadItem = [self extractCacheItemWithKey:broadKey userId:userId error:&localError];
        if (localError)
        {
            if (error)
            {
                *error = localError;
            }
            return nil;
        }
        return broadItem;
    }
    return nil;//Nothing suitable
}

- (ADTokenCacheItem *)findFamilyItemForUser:(ADUserIdentifier *)userIdentifier
                                      error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!userIdentifier)
    {
        return nil;
    }
    
    if (!userIdentifier.userId)
    {
        return nil;
    }
    
    NSArray* items = [[self tokenCacheStore] getItemsWithKey:nil
                                                      userId:userIdentifier.userId
                                                       error:error];
    if (!items || items.count == 0)
    {
        return nil;
    }
    
    for (ADTokenCacheItem* item in items)
    {
        if (![NSString adIsStringNilOrBlank:item.familyId] &&
            ![NSString adIsStringNilOrBlank:item.refreshToken])
        {
            // Return the first item we see with a family ID and a RT
            return item;
        }
    }
    
    return nil;
}

//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult*)result
                  cacheItem:(ADTokenCacheItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
       requestCorrelationId:(NSUUID*)requestCorrelationId
{
    [self updateCacheToResult:result
                cacheInstance:self.tokenCacheStore
                    cacheItem:cacheItem
             withRefreshToken:refreshToken
         requestCorrelationId:requestCorrelationId];
}

- (void)updateCacheToResult:(ADAuthenticationResult*)result
              cacheInstance:(id<ADTokenCacheAccessor>)tokenCacheStoreInstance
                  cacheItem:(ADTokenCacheItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
       requestCorrelationId:(NSUUID*)requestCorrelationId
{
    if(![ADAuthenticationContext handleNilOrEmptyAsResult:result argumentName:@"result" authenticationResult:&result])
    {
        return;
    }
    
    if (!tokenCacheStoreInstance)
    {
        return;
    }
    
    if (AD_SUCCEEDED == result.status)
    {
        if(![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheItem argumentName:@"tokenCacheItem" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheItem.resource argumentName:@"resource" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheItem.accessToken argumentName:@"accessToken" authenticationResult:&result])
        {
            return;
        }
        
        //In case of success we use explicitly the item that comes back in the result:
        cacheItem = result.tokenCacheItem;
        NSString* savedRefreshToken = cacheItem.refreshToken;
        if (result.multiResourceRefreshToken)
        {
            AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Storing multi-resource refresh token for authority: %@", self.authority);
            
            //If the server returned a multi-resource refresh token, we break
            //the item into two: one with the access token and no refresh token and
            //another one with the broad refresh token and no access token and no resource.
            //This breaking is useful for further updates on the cache and quick lookups
            ADTokenCacheItem* multiRefreshTokenItem = [cacheItem copy];
            cacheItem.refreshToken = nil;
            
            multiRefreshTokenItem.accessToken = nil;
            multiRefreshTokenItem.resource = nil;
            multiRefreshTokenItem.expiresOn = nil;
            [tokenCacheStoreInstance addOrUpdateItem:multiRefreshTokenItem error:nil];
            SAFE_ARC_RELEASE(multiRefreshTokenItem);
        }
        
        AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Storing access token for resource: %@", cacheItem.resource);
        [tokenCacheStoreInstance addOrUpdateItem:cacheItem error:nil];
        cacheItem.refreshToken = savedRefreshToken;//Restore for the result
    }
    else
    {
        if (AD_ERROR_INVALID_REFRESH_TOKEN == result.error.code)
        {//Bad refresh token. Remove it from the cache:
            if(![ADAuthenticationContext handleNilOrEmptyAsResult:cacheItem argumentName:@"cacheItem" authenticationResult:&result]
               || ![ADAuthenticationContext handleNilOrEmptyAsResult:cacheItem.resource argumentName:@"cacheItem.resource" authenticationResult:&result]
               || ![ADAuthenticationContext handleNilOrEmptyAsResult:refreshToken argumentName:@"refreshToken" authenticationResult:&result])
            {
                return;
            }
            
            BOOL removed = NO;
            //The refresh token didn't work. We need to tombstone this refresh item in the cache.
            ADTokenCacheKey* exactKey = [cacheItem extractKey:nil];
            if (exactKey)
            {
                ADTokenCacheItem* existing = [tokenCacheStoreInstance getItemWithKey:exactKey userId:cacheItem.userInformation.userId error:nil];
                if ([refreshToken isEqualToString:existing.refreshToken])//If still there, attempt to remove
                {
                    AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Tombstoning cache for resource: %@", cacheItem.resource);
                    //update tombstone property before update the tombstone in cache
                    [existing setTombstone:[NSMutableDictionary dictionaryWithDictionary:@{ @"correlationId" : [requestCorrelationId UUIDString],
                                                                                            @"errorDetails" : [result.error errorDetails],
                                                                                            @"protocolCode" : [result.error protocolCode],
                                                                                            @"bundleId" : [[NSBundle mainBundle] bundleIdentifier] ? [[NSBundle mainBundle] bundleIdentifier] : @""}]];
                    [tokenCacheStoreInstance addOrUpdateItem:existing error:nil];
                    removed = YES;
                }
            }
            
            if (!removed)
            {
                //Now try finding a broad refresh token in the cache and tombstone it accordingly
                ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:self.authority resource:nil clientId:cacheItem.clientId error:nil];
                if (broadKey)
                {
                    ADTokenCacheItem* broadItem = [tokenCacheStoreInstance getItemWithKey:broadKey userId:cacheItem.userInformation.userId error:nil];
                    if (broadItem && [refreshToken isEqualToString:broadItem.refreshToken])//Remove if still there
                    {
                        AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Tombstoning multi-resource refresh token for authority: %@", self.authority);
                        //update tombstone property before update the tombstone in cache
                        [broadItem setTombstone:[NSMutableDictionary dictionaryWithDictionary:@{ @"correlationId" : [requestCorrelationId UUIDString],
                                                                                                 @"errorDetails" : [result.error errorDetails],
                                                                                                 @"protocolCode" : [result.error protocolCode],
                                                                                                 @"bundleId" : [[NSBundle mainBundle] bundleIdentifier] ? [[NSBundle mainBundle] bundleIdentifier] : @""}]];
                        [tokenCacheStoreInstance addOrUpdateItem:broadItem error:nil];
                    }
                }
            }
        }
        
    }
}

@end

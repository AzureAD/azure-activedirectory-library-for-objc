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

#import "ADAuthenticationContext+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADTokenCacheKey.h"
#import "ADUserInformation.h"

@implementation ADAuthenticationRequest (TokenCaching)

//Gets an item from the cache, where userId may be nil. Raises error, if items for multiple users
//are present and user id is not specified.
- (ADTokenCacheItem*)extractCacheItemWithKey:(ADTokenCacheKey *)key
                                      userId:(ADUserIdentifier *)userId
                               correlationId:(NSUUID *)correlationId
                                       error:(ADAuthenticationError* __autoreleasing*)error
{
    if (!key || !self.tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    
    ADAuthenticationError* localError = nil;
    ADTokenCacheItem* item = [self.tokenCacheStore getItemWithKey:key userId:userId.userId correlationId:correlationId error:&localError];
    if (!item && !localError && userId)
    {
        //ADFS fix, where the userId is not received by the server, but can be passed to the API:
        //We didn't find element with the userId, try finding an item with a blank userId:
        item = [self.tokenCacheStore getItemWithKey:key userId:@"" correlationId:correlationId error:&localError];
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
                             correlationId:(NSUUID *)correlationId
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
    ADTokenCacheItem* item = [self extractCacheItemWithKey:key
                                                    userId:userId
                                             correlationId:correlationId
                                                     error:&localError];
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
            AD_LOG_WARN(@"Unexpected error", correlationId, localError.errorDetails);
            return nil;//Recover
        }
        ADTokenCacheItem* broadItem = [self extractCacheItemWithKey:broadKey
                                                             userId:userId
                                                      correlationId:correlationId
                                                              error:&localError];
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
                              correlationId:(NSUUID *)correlationId
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
                                               correlationId:correlationId
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
            [tokenCacheStoreInstance addOrUpdateItem:multiRefreshTokenItem correlationId:requestCorrelationId error:nil];
            SAFE_ARC_RELEASE(multiRefreshTokenItem);
        }
        
        AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Storing access token for resource: %@", cacheItem.resource);
        [tokenCacheStoreInstance addOrUpdateItem:cacheItem correlationId:requestCorrelationId error:nil];
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
                ADTokenCacheItem* existing = [tokenCacheStoreInstance getItemWithKey:exactKey userId:cacheItem.userInformation.userId correlationId:requestCorrelationId error:nil];
                if ([refreshToken isEqualToString:existing.refreshToken])//If still there, attempt to remove
                {
                    AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Tombstoning cache for resource: %@", cacheItem.resource);
                    //update tombstone property before update the tombstone in cache
                    [existing makeTombstone:@{ @"correlationId" : [requestCorrelationId UUIDString],
                                               @"errorDetails" : [result.error errorDetails],
                                               @"protocolCode" : [result.error protocolCode] }];
                    [tokenCacheStoreInstance addOrUpdateItem:existing correlationId:requestCorrelationId error:nil];
                    removed = YES;
                }
            }
            
            if (!removed)
            {
                //Now try finding a broad refresh token in the cache and tombstone it accordingly
                ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:self.authority resource:nil clientId:cacheItem.clientId error:nil];
                if (broadKey)
                {
                    ADTokenCacheItem* broadItem = [tokenCacheStoreInstance getItemWithKey:broadKey userId:cacheItem.userInformation.userId correlationId:requestCorrelationId error:nil];
                    if (broadItem && [refreshToken isEqualToString:broadItem.refreshToken])//Remove if still there
                    {
                        AD_LOG_VERBOSE_F(@"Token cache store", requestCorrelationId, @"Tombstoning multi-resource refresh token for authority: %@", self.authority);
                        //update tombstone property before update the tombstone in cache
                        [broadItem makeTombstone:@{ @"correlationId" : [requestCorrelationId UUIDString],
                                                    @"errorDetails" : [result.error errorDetails],
                                                    @"protocolCode" : [result.error protocolCode] }];
                        [tokenCacheStoreInstance addOrUpdateItem:broadItem correlationId:requestCorrelationId error:nil];
                    }
                }
            }
        }
        
    }
}

@end

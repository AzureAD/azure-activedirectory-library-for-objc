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
#import "ADAuthenticationRequest.h"

@implementation ADAuthenticationRequest (TokenCaching)

//Gets an item from the cache, where userId may be nil. Raises error, if items for multiple users
//are present and user id is not specified.
- (ADTokenCacheItem*)extractCacheItemWithKey:(ADTokenCacheKey *)key
                                      userId:(ADUserIdentifier *)userId
                                       error:(ADAuthenticationError* __autoreleasing*)error
{
    id<ADTokenCacheAccessor> tokenCacheStore = [_context tokenCacheStore];
    if (!key || !tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    
    ADAuthenticationError* localError = nil;
    ADTokenCacheItem* item = [tokenCacheStore getItemWithKey:key userId:userId.userId correlationId:_correlationId error:&localError];
    if (!item && !localError && userId)
    {
        //ADFS fix, where the userId is not received by the server, but can be passed to the API:
        //We didn't find element with the userId, try finding an item with a blank userId:
        item = [tokenCacheStore getItemWithKey:key userId:@"" correlationId:_correlationId error:&localError];
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
    
    id<ADTokenCacheAccessor> tokenCacheStore = [_context tokenCacheStore];
    
    if (!key || !tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    ADAuthenticationError* localError = nil;
    ADTokenCacheItem* item = [self extractCacheItemWithKey:key
                                                    userId:userId
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
    [tokenCacheStore removeItem:item error:nil];
    
    if (![NSString adIsStringNilOrBlank:key.resource])
    {
        //The request came for specific resource. Try returning a multi-resource refresh token:
        ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:_context.authority
                                                                       resource:nil
                                                                       clientId:key.clientId
                                                                          error:&localError];
        if (!broadKey)
        {
            AD_LOG_WARN(@"Unexpected error", _correlationId, localError.errorDetails);
            return nil;//Recover
        }
        ADTokenCacheItem* broadItem = [self extractCacheItemWithKey:broadKey
                                                             userId:userId
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

//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult *)result
                  cacheItem:(ADTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
{

    if(![ADAuthenticationContext handleNilOrEmptyAsResult:result argumentName:@"result" authenticationResult:&result])
    {
        return;
    }
    
    if (![_context tokenCacheStore])
    {
        return;
    }
    
    if (AD_SUCCEEDED == result.status)
    {
        ADTokenCacheItem* item = [result tokenCacheItem];
        
        // Validate that this item is a valid item to add.
        if(![ADAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"tokenCacheItem" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"resource" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:item argumentName:@"accessToken" authenticationResult:&result])
        {
            AD_LOG_WARN(@"Told to update cache to an invalid token cache item", _correlationId, nil);
            return;
        }
        
        [self updateCacheToItem:item
                           MRRT:[result multiResourceRefreshToken]];
        return;
    }
    
    if (result.error.code != AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED)
    {
        return;
    }
    
    // Only remove tokens from the cache if we get an invalid_grant from the server
    if (![result.error.protocolCode isEqualToString:@"invalid_grant"])
    {
        return;
    }
    
    [self removeItemFromCache:cacheItem
                 refreshToken:refreshToken
                        error:result.error];
}

- (void)updateCacheToItem:(ADTokenCacheItem *)cacheItem
                     MRRT:(BOOL)isMRRT
{
    id<ADTokenCacheAccessor> tokenCacheStore = [_context tokenCacheStore];
    
    NSString* savedRefreshToken = cacheItem.refreshToken;
    if (isMRRT)
    {
        AD_LOG_VERBOSE_F(@"Token cache store", _correlationId, @"Storing multi-resource refresh token for authority: %@", _context.authority);
        
        //If the server returned a multi-resource refresh token, we break
        //the item into two: one with the access token and no refresh token and
        //another one with the broad refresh token and no access token and no resource.
        //This breaking is useful for further updates on the cache and quick lookups
        ADTokenCacheItem* multiRefreshTokenItem = [cacheItem copy];
        cacheItem.refreshToken = nil;
        
        multiRefreshTokenItem.accessToken = nil;
        multiRefreshTokenItem.resource = nil;
        multiRefreshTokenItem.expiresOn = nil;
        [tokenCacheStore addOrUpdateItem:multiRefreshTokenItem correlationId:_correlationId error:nil];
        SAFE_ARC_RELEASE(multiRefreshTokenItem);
    }
    
    AD_LOG_VERBOSE_F(@"Token cache store", _correlationId, @"Storing access token for resource: %@", cacheItem.resource);
    [tokenCacheStore addOrUpdateItem:cacheItem correlationId:_correlationId error:nil];
    cacheItem.refreshToken = savedRefreshToken;//Restore for the result
}

- (void)removeItemFromCache:(ADTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                      error:(ADAuthenticationError *)error
{
    id<ADTokenCacheAccessor> tokenCacheStore = [_context tokenCacheStore];
    
    if (!cacheItem && !refreshToken)
    {
        return;
    }
    
    BOOL removed = NO;
    //The refresh token didn't work. We need to tombstone this refresh item in the cache.
    ADTokenCacheKey* exactKey = [cacheItem extractKey:nil];
    if (exactKey)
    {
        ADTokenCacheItem* existing = [tokenCacheStore getItemWithKey:exactKey userId:cacheItem.userInformation.userId correlationId:_correlationId error:nil];
        if ([refreshToken isEqualToString:existing.refreshToken])//If still there, attempt to remove
        {
            AD_LOG_VERBOSE_F(@"Token cache store", _correlationId, @"Tombstoning cache for resource: %@", cacheItem.resource);
            //update tombstone property before update the tombstone in cache
            [existing makeTombstone:@{ @"correlationId" : [_correlationId UUIDString],
                                       @"errorDetails" : [error errorDetails],
                                       @"protocolCode" : [error protocolCode] }];
            [tokenCacheStore addOrUpdateItem:existing correlationId:_correlationId error:nil];
            removed = YES;
        }
    }
    
    if (!removed)
    {
        //Now try finding a broad refresh token in the cache and tombstone it accordingly
        ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:_context.authority resource:nil clientId:cacheItem.clientId error:nil];
        if (broadKey)
        {
            ADTokenCacheItem* broadItem = [tokenCacheStore getItemWithKey:broadKey userId:cacheItem.userInformation.userId correlationId:_correlationId error:nil];
            if (broadItem && [refreshToken isEqualToString:broadItem.refreshToken])//Remove if still there
            {
                AD_LOG_VERBOSE_F(@"Token cache store", _correlationId, @"Tombstoning multi-resource refresh token for authority: %@", _context.authority);
                //update tombstone property before update the tombstone in cache
                [broadItem makeTombstone:@{ @"correlationId" : [_correlationId UUIDString],
                                            @"errorDetails" : [error errorDetails],
                                            @"protocolCode" : [error protocolCode] }];
                [tokenCacheStore addOrUpdateItem:broadItem correlationId:_correlationId error:nil];
            }
        }
    }
}

@end

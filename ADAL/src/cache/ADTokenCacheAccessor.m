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

#import "ADTokenCacheAccessor.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheKey.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryCacheEvent.h"
#import "ADTelemetryEventStrings.h"

@implementation ADTokenCacheAccessor

+ (NSString*)familyClientId:(NSString*)familyID
{
    if (!familyID)
    {
        familyID = @"1";
    }
    
    return [NSString stringWithFormat:@"foci-%@", familyID];
}

- (id)initWithDataSource:(id<ADTokenCacheDataSource>)dataSource
               authority:(NSString *)authority
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _dataSource = dataSource;
    SAFE_ARC_RETAIN(dataSource);
    
    _authority = authority;
    SAFE_ARC_RETAIN(authority);
    
    return self;
}

- (id<ADTokenCacheDataSource>)dataSource
{
    return _dataSource;
}

- (ADTokenCacheItem *)getItemForUser:(ADUserIdentifier *)identifier
                            resource:(NSString *)resource
                            clientId:(NSString *)clientId
                             context:(id<ADRequestContext>)context
                               error:(ADAuthenticationError * __autoreleasing *)error
{
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:_authority
                                                    resource:resource
                                                    clientId:clientId
                                                       error:error];
    if (!key)
    {
        return nil;
    }
    
    return [_dataSource getItemWithKey:key
                                userId:identifier.userId
                         correlationId:[context correlationId]
                                 error:error];
}

/*!
    Returns a AT/RT Token Cache Item for the given parameters. The RT in this item will only be good
    for the given resource. If no RT is returned in the item then a MRRT or FRT should be used (if
    available).
 */
- (ADTokenCacheItem *)getATRTItemForUser:(ADUserIdentifier *)identifier
                                resource:(NSString *)resource
                                clientId:(NSString *)clientId
                                 context:(id<ADRequestContext>)context
                                   error:(ADAuthenticationError * __autoreleasing *)error
{
    [[ADTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:@"token_cache_lookup"];
    
    ADTokenCacheItem* item = [self getItemForUser:identifier resource:resource clientId:clientId context:context error:error];
    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_lookup"
                                                                       context:context];
    [event setTokenType:@"access token"];
    [event setStatus:item? @"succeeded" : @"failed"];
    [[ADTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    SAFE_ARC_RELEASE(event);
    return item;
}

/*!
    Returns a Multi-Resource Refresh Token (MRRT) Cache Item for the given parameters. A MRRT can
    potentially be used for many resources for that given user, client ID and authority.
 */
- (ADTokenCacheItem *)getMRRTItemForUser:(ADUserIdentifier *)identifier
                                clientId:(NSString *)clientId
                                 context:(id<ADRequestContext>)context
                                   error:(ADAuthenticationError * __autoreleasing *)error
{
    [[ADTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:@"token_cache_lookup"];
    ADTokenCacheItem* item = [self getItemForUser:identifier resource:nil clientId:clientId context:context error:error];
    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_lookup"
                                                                     requestId:[context telemetryRequestId]
                                                                 correlationId:[context correlationId]];
    [event setTokenType:@"multi-resource refresh token"];
    [event setMRRTStatus:AD_TELEMETRY_NOT_FOUND];
    if (item)
    {
        [event setIsMRRT:AD_TELEMETRY_YES];
        [event setMRRTStatus:AD_TELEMETRY_TRIED];
    }
    [event setStatus:item? @"succeeded" : @"failed"];
    [[ADTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    SAFE_ARC_RELEASE(event);
    return item;
}

/*!
    Returns a Family Refresh Token for the given authority, user and family ID, if available. A FRT can
    be used for many resources within a given family of client IDs.
 */
- (ADTokenCacheItem *)getFRTItemForUser:(ADUserIdentifier *)identifier
                               familyId:(NSString *)familyId
                                context:(id<ADRequestContext>)context
                                  error:(ADAuthenticationError * __autoreleasing *)error
{
    [[ADTelemetry sharedInstance] startEvent:context.telemetryRequestId eventName:@"token_cache_lookup"];
    
    NSString* fociClientId = [ADTokenCacheAccessor familyClientId:familyId];
    ADTokenCacheItem* item = [self getItemForUser:identifier resource:nil clientId:fociClientId context:context error:error];

    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_lookup"
                                                                       context:context];
    [event setTokenType:@"family refresh token"];
    [event setFRTStatus:AD_TELEMETRY_NOT_FOUND];
    if (item)
    {
        [event setIsFRT:AD_TELEMETRY_YES];
        [event setFRTStatus:AD_TELEMETRY_TRIED];
    }
    [event setStatus:item? @"succeeded" : @"failed"];
    [[ADTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    SAFE_ARC_RELEASE(event);
    return item;
}

- (ADTokenCacheItem*)getADFSUserTokenForResource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                         context:(id<ADRequestContext>)context
                                           error:(ADAuthenticationError * __autoreleasing *)error
{
    // ADFS fix: When talking to ADFS directly we can get ATs and RTs (but not MRRTs or FRTs) without
    // id tokens. In those cases we do not know who they belong to and cache them with a blank userId
    // (@"").
    
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:_authority
                                                    resource:resource
                                                    clientId:clientId
                                                       error:error];
    if (!key)
    {
        return nil;
    }

    [[ADTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:@"token_cache_lookup"];
    ADTokenCacheItem* item = [_dataSource getItemWithKey:key userId:@"" correlationId:[context correlationId] error:error];
    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_lookup"
                                                                       context:context];
    [event setTokenType:@"ADFS access token/refresh token"];
    [event setRTStatus:AD_TELEMETRY_NOT_FOUND];
    if ([item refreshToken])
    {
        [event setIsRT:AD_TELEMETRY_YES];
        [event setRTStatus:AD_TELEMETRY_TRIED];
    }
    [event setStatus:item? @"succeeded" : @"failed"];
    [[ADTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    SAFE_ARC_RELEASE(event);
    return item;
}


//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult *)result
                  cacheItem:(ADTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                    context:(id<ADRequestContext>)context
{
    
    if(!result)
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
            AD_LOG_WARN(@"Told to update cache to an invalid token cache item", [context correlationId], nil);
            return;
        }
        
        [self updateCacheToItem:item
                           MRRT:[result multiResourceRefreshToken]
                        context:context];
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
                      context:context
                        error:result.error];
}

- (void)updateCacheToItem:(ADTokenCacheItem *)cacheItem
                     MRRT:(BOOL)isMRRT
                  context:(id<ADRequestContext>)context
{
    NSUUID* correlationId = [context correlationId];
    NSString* telemetryRequestId = [context telemetryRequestId];
    
    NSString* savedRefreshToken = cacheItem.refreshToken;
    if (isMRRT)
    {
        AD_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Storing multi-resource refresh token for authority: %@", _authority);
        [[ADTelemetry sharedInstance] startEvent:telemetryRequestId eventName:@"token_cache_write"];
        
        //If the server returned a multi-resource refresh token, we break
        //the item into two: one with the access token and no refresh token and
        //another one with the broad refresh token and no access token and no resource.
        //This breaking is useful for further updates on the cache and quick lookups
        ADTokenCacheItem* multiRefreshTokenItem = [cacheItem copy];
        cacheItem.refreshToken = nil;
        
        multiRefreshTokenItem.accessToken = nil;
        multiRefreshTokenItem.resource = nil;
        multiRefreshTokenItem.expiresOn = nil;
        [_dataSource addOrUpdateItem:multiRefreshTokenItem correlationId:correlationId error:nil];
        ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_write"
                                                                           context:context];
        [event setIsMRRT:AD_TELEMETRY_YES];
        [event setTokenType:@"multi-resource refresh token"];
        [[ADTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
        SAFE_ARC_RELEASE(event);
        
        // If the item is also a Family Refesh Token (FRT) we update the FRT
        // as well so we have a guaranteed spot to look for the most recent FRT.
        NSString* familyId = cacheItem.familyId;
        if (familyId)
        {
            [[ADTelemetry sharedInstance] startEvent:telemetryRequestId eventName:@"token_cache_write"];
            
            ADTokenCacheItem* frtItem = [multiRefreshTokenItem copy];
            NSString* fociClientId = [ADTokenCacheAccessor familyClientId:familyId];
            frtItem.clientId = fociClientId;
            [_dataSource addOrUpdateItem:frtItem correlationId:correlationId error:nil];
            SAFE_ARC_RELEASE(frtItem);
            
            ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_write"
                                                                               context:context];
            [event setIsFRT:AD_TELEMETRY_YES];
            [event setTokenType:@"family refresh token"];
            [[ADTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
            SAFE_ARC_RELEASE(event);
        }
        SAFE_ARC_RELEASE(multiRefreshTokenItem);
    }
    
    AD_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Storing access token for resource: %@", cacheItem.resource);
    [[ADTelemetry sharedInstance] startEvent:telemetryRequestId eventName:@"token_cache_write"];
    [_dataSource addOrUpdateItem:cacheItem correlationId:correlationId error:nil];
    cacheItem.refreshToken = savedRefreshToken;//Restore for the result
    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_write"
                                                                       context:context];
    [event setTokenType:@"access token"];
    [[ADTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
    SAFE_ARC_RELEASE(event);
}

- (void)removeItemFromCache:(ADTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                    context:(id<ADRequestContext>)context
                      error:(ADAuthenticationError *)error
{
    if (!cacheItem && !refreshToken)
    {
        return;
    }
    
    NSUUID* correlationId = [context correlationId];
    [[ADTelemetry sharedInstance] startEvent:[context telemetryRequestId] eventName:@"token_cache_delete_token"];
    BOOL removed = NO;
    //The refresh token didn't work. We need to tombstone this refresh item in the cache.
    ADTokenCacheKey* exactKey = [cacheItem extractKey:nil];
    if (exactKey)
    {
        ADTokenCacheItem* existing = [_dataSource getItemWithKey:exactKey userId:cacheItem.userInformation.userId correlationId:correlationId error:nil];
        if ([refreshToken isEqualToString:existing.refreshToken])//If still there, attempt to remove
        {
            AD_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Tombstoning cache for resource: %@", cacheItem.resource);
            //update tombstone property before update the tombstone in cache
            [existing makeTombstone:@{ @"correlationId" : [correlationId UUIDString],
                                       @"errorDetails" : [error errorDetails],
                                       @"protocolCode" : [error protocolCode] }];
            [_dataSource addOrUpdateItem:existing correlationId:correlationId error:nil];
            removed = YES;
        }
    }
    
    if (!removed)
    {
        //Now try finding a broad refresh token in the cache and tombstone it accordingly
        ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:_authority
                                                             resource:nil
                                                             clientId:cacheItem.clientId
                                                                error:nil];
        if (broadKey)
        {
            ADTokenCacheItem* broadItem = [_dataSource getItemWithKey:broadKey userId:cacheItem.userInformation.userId correlationId:correlationId error:nil];
            if (broadItem && [refreshToken isEqualToString:broadItem.refreshToken])//Remove if still there
            {
                AD_LOG_VERBOSE_F(@"Token cache store", correlationId, @"Tombstoning multi-resource refresh token for authority: %@", _authority);
                //update tombstone property before update the tombstone in cache
                [broadItem makeTombstone:@{ @"correlationId" : [correlationId UUIDString],
                                            @"errorDetails" : [error errorDetails],
                                            @"protocolCode" : [error protocolCode] }];
                [_dataSource addOrUpdateItem:broadItem correlationId:correlationId error:nil];
            }
        }
    }
    ADTelemetryCacheEvent* event = [[ADTelemetryCacheEvent alloc] initWithName:@"token_cache_delete_token"
                                                                       context:context];
    [[ADTelemetry sharedInstance] stopEvent:[context telemetryRequestId] event:event];
    SAFE_ARC_RELEASE(event);
}

@end

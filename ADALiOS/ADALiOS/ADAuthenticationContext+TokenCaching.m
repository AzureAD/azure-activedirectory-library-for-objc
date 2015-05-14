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

@implementation ADAuthenticationContext (TokenCaching)

//Gets an item from the cache, where userId may be nil. Raises error, if items for multiple users
//are present and user id is not specified.
- (ADTokenCacheStoreItem*)extractCacheItemWithKey:(ADTokenCacheStoreKey*)key
                                           userId:(NSString*)userId
                                            error:(ADAuthenticationError* __autoreleasing*)error
{
    if (!key || !self.tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    
    ADAuthenticationError* localError;
    ADTokenCacheStoreItem* item = [self.tokenCacheStore getItemWithKey:key userId:userId error:&localError];
    if (!item && !localError && userId)
    {//ADFS fix, where the userId is not received by the server, but can be passed to the API:
        //We didn't find element with the userId, try finding an item with nil userId:
        NSArray* items = [self.tokenCacheStore getItemsWithKey:key error:&localError];
        if(items.count) {
            item = items.firstObject;
        }else{
            item = nil;
        }
        
        if (item && item.userInformation)
        {
            item = nil;//Different user id, just clear.
        }
    }
    if (error && localError)
    {
        *error = localError;
    }
    return item;
}

//Checks the cache for item that can be used to get directly or indirectly an access token.
//Checks the multi-resource refresh tokens too.
- (ADTokenCacheStoreItem*)findCacheItemWithKey:(ADTokenCacheStoreKey*) key
                                        userId:(NSString*) userId
                                useAccessToken:(BOOL*) useAccessToken
                                         error:(ADAuthenticationError* __autoreleasing*) error
{
    if (!key || !self.tokenCacheStore)
    {
        return nil;//Nothing to return
    }
    ADAuthenticationError* localError;
    ADTokenCacheStoreItem* item = [self extractCacheItemWithKey:key userId:userId error:&localError];
    if (localError)
    {
        if (error)
        {
            *error = localError;
        }
        return nil;//Quick return if an error was detected.
    }
    
    if (item)
    {
        *useAccessToken = item.accessToken && !item.isExpired;
        if (*useAccessToken)
        {
            return item;
        }
        else if (![NSString adIsStringNilOrBlank:item.refreshToken])
        {
            return item;//Suitable direct refresh token found.
        }
        else
        {
            //We have a cache item that cannot be used anymore, remove it from the cache:
            [self.tokenCacheStore removeItemWithKey:key userId:userId error:nil];
        }
    }
    *useAccessToken = false;//No item with suitable access token exists
    
    if (![NSString adIsStringNilOrBlank:key.resource])
    {
        //The request came for specific resource. Try returning a multi-resource refresh token:
        ADTokenCacheStoreKey* broadKey = [ADTokenCacheStoreKey keyWithAuthority:self.authority
                                                                       resource:nil
                                                                       clientId:key.clientId
                                                                          error:&localError];
        if (!broadKey)
        {
            AD_LOG_WARN(@"Unexpected error", localError.errorDetails);
            return nil;//Recover
        }
        ADTokenCacheStoreItem* broadItem = [self extractCacheItemWithKey:broadKey userId:userId error:&localError];
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

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheStoreItem*)item
               useAccessToken:(BOOL)useAccessToken
                samlAssertion:(NSString*)samlAssertion
                assertionType:(ADAssertionType)assertionType
                     resource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSString*)redirectUri
                       userId:(NSString*)userId
                correlationId:(NSUUID*)correlationId
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(item);
    HANDLE_ARGUMENT(resource);
    HANDLE_ARGUMENT(clientId);
    HANDLE_ARGUMENT(correlationId);//Should have been set before this call
    
    if (useAccessToken)
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:nil];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheStoreItem:item multiResourceRefreshToken:NO];
        completionBlock(result);
        return;
    }
    
    if ([NSString adIsStringNilOrBlank:item.refreshToken])
    {
        completionBlock([ADAuthenticationResult resultFromError:
                         [ADAuthenticationError unexpectedInternalError:@"Attempting to use an item without refresh token."]]);
        return;
    }
    
    //Now attempt to use the refresh token of the passed cache item:
    [self internalAcquireTokenByRefreshToken:item.refreshToken
                                    clientId:clientId
                                 redirectUri: (NSString*) redirectUri
                                    resource:resource
                                      userId:item.userInformation.userId
                                   cacheItem:item
                           validateAuthority:NO /* Done by the caller. */
                               correlationId:correlationId
                             completionBlock:^(ADAuthenticationResult *result)
     {
         //Asynchronous block:
         if ([ADAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         //Try other means of getting access token result:
         if (!item.multiResourceRefreshToken)//Try multi-resource refresh token if not currently trying it
         {
             ADTokenCacheStoreKey* broadKey = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:nil clientId:clientId error:nil];
             if (broadKey)
             {
                 BOOL useAccessToken;
                 ADAuthenticationError* error = nil;
                 ADTokenCacheStoreItem* broadItem = [self findCacheItemWithKey:broadKey userId:userId useAccessToken:&useAccessToken error:&error];
                 if (error)
                 {
                     completionBlock([ADAuthenticationResult resultFromError:error]);
                     return;
                 }
                 
                 if (broadItem)
                 {
                     if (!broadItem.multiResourceRefreshToken)
                     {
                         AD_LOG_WARN(@"Unexpected", @"Multi-resource refresh token expected here.");
                         //Recover (avoid infinite recursion):
                         completionBlock(result);
                         return;
                     }
                     
                     //Call recursively with the cache item containing a multi-resource refresh token:
                     [self attemptToUseCacheItem:broadItem
                                  useAccessToken:NO
                                   samlAssertion:samlAssertion
                                   assertionType:assertionType
                                        resource:resource
                                        clientId:clientId
                                     redirectUri:redirectUri
                                          userId:userId
                                   correlationId:correlationId
                                 completionBlock:completionBlock];
                     return;//The call above takes over, no more processing
                 }//broad item
             }//key
         }//!item.multiResourceRefreshToken
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestTokenByAssertion: samlAssertion
                         assertionType: assertionType
                              resource: resource
                              clientId: clientId
                                 scope: nil//For future use
                         correlationId: correlationId
                            completion: completionBlock];
     }];//End of the refreshing token completion block, executed asynchronously.
}


/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
-(void) attemptToUseCacheItem: (ADTokenCacheStoreItem*) item
               useAccessToken: (BOOL) useAccessToken
                     resource: (NSString*) resource
                     clientId: (NSString*) clientId
                  redirectUri: (NSURL*) redirectUri
               promptBehavior: (ADPromptBehavior) promptBehavior
                       silent: (BOOL) silent
                       userId: (NSString*) userId
         extraQueryParameters: (NSString*) queryParams
                correlationId: (NSUUID*) correlationId
              completionBlock: (ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(item);
    HANDLE_ARGUMENT(resource);
    HANDLE_ARGUMENT(clientId);
    HANDLE_ARGUMENT(correlationId);//Should have been set before this call
    
    if (useAccessToken)
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:nil];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheStoreItem:item multiResourceRefreshToken:NO];
        completionBlock(result);
        return;
    }
    
    if ([NSString adIsStringNilOrBlank:item.refreshToken])
    {
        completionBlock([ADAuthenticationResult resultFromError:
                         [ADAuthenticationError unexpectedInternalError:@"Attempting to use an item without refresh token."]]);
        return;
    }
    
    //Now attempt to use the refresh token of the passed cache item:
    [self internalAcquireTokenByRefreshToken:item.refreshToken
                                    clientId:clientId
                                 redirectUri:[redirectUri absoluteString]
                                    resource:resource
                                      userId:item.userInformation.userId
                                   cacheItem:item
                           validateAuthority:NO /* Done by the caller. */
                               correlationId:correlationId
                             completionBlock:^(ADAuthenticationResult *result)
     {
         //Asynchronous block:
         if ([ADAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         //Try other means of getting access token result:
         if (!item.multiResourceRefreshToken)//Try multi-resource refresh token if not currently trying it
         {
             ADTokenCacheStoreKey* broadKey = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:nil clientId:clientId error:nil];
             if (broadKey)
             {
                 BOOL useAccessToken;
                 ADAuthenticationError* error;
                 ADTokenCacheStoreItem* broadItem = [self findCacheItemWithKey:broadKey userId:userId useAccessToken:&useAccessToken error:&error];
                 if (error)
                 {
                     completionBlock([ADAuthenticationResult resultFromError:error]);
                     return;
                 }
                 
                 if (broadItem)
                 {
                     if (!broadItem.multiResourceRefreshToken)
                     {
                         AD_LOG_WARN(@"Unexpected", @"Multi-resource refresh token expected here.");
                         //Recover (avoid infinite recursion):
                         completionBlock(result);
                         return;
                     }
                     
                     //Call recursively with the cache item containing a multi-resource refresh token:
                     [self attemptToUseCacheItem:broadItem
                                  useAccessToken:NO
                                        resource:resource
                                        clientId:clientId
                                     redirectUri:redirectUri
                                  promptBehavior:promptBehavior
                                          silent:silent
                                          userId:userId
                            extraQueryParameters:queryParams
                                   correlationId:correlationId
                                 completionBlock:completionBlock];
                     return;//The call above takes over, no more processing
                 }//broad item
             }//key
         }//!item.multiResourceRefreshToken
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestTokenWithResource: resource
                               clientId: clientId
                            redirectUri: redirectUri
                         promptBehavior: promptBehavior
                                 silent: silent
                                 userId: userId
                                  scope: nil
                   extraQueryParameters: queryParams
                          correlationId:correlationId
                        completionBlock: completionBlock];
     }];//End of the refreshing token completion block, executed asynchronously.
}

//Understands and processes the access token response:
- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                         forItem:(ADTokenCacheStoreItem*)item
                                     fromRefresh:(BOOL)fromRefreshTokenWorkflow
                            requestCorrelationId:(NSUUID*)requestCorrelationId
{
    THROW_ON_NIL_ARGUMENT(response);
    THROW_ON_NIL_ARGUMENT(item);
    AD_LOG_VERBOSE(@"Token extraction", @"Attempt to extract the data from the server response.");
    
    NSString* responseId = [response objectForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    NSUUID* responseUUID;
    if (![NSString adIsStringNilOrBlank:responseId])
    {
        responseUUID = [[NSUUID alloc] initWithUUIDString:responseId];
        if (!responseUUID)
        {
            AD_LOG_INFO_F(@"Bad correlation id", @"The received correlation id is not a valid UUID. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
        else if (![requestCorrelationId isEqual:responseUUID])
        {
            AD_LOG_INFO_F(@"Correlation id mismatch", @"Mismatch between the sent correlation id and the received one. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
    }
    else
    {
        AD_LOG_INFO_F(@"Missing correlation id", @"No correlation id received for request with correlation id: %@", [requestCorrelationId UUIDString]);
    }
    
    ADAuthenticationError* error = [ADAuthenticationContext errorFromDictionary:response errorCode:(fromRefreshTokenWorkflow) ? AD_ERROR_INVALID_REFRESH_TOKEN : AD_ERROR_AUTHENTICATION];
    if (error)
    {
        return [ADAuthenticationResult resultFromError:error];
    }
    
    NSString* accessToken = [response objectForKey:OAUTH2_ACCESS_TOKEN];
    if (![NSString adIsStringNilOrBlank:accessToken])
    {
        item.authority = self.authority;
        item.accessToken = accessToken;
        
        // Token response
        id      expires_in = [response objectForKey:@"expires_in"];
        NSDate *expires    = nil;
        
        if ( expires_in != nil )
        {
            if ( [expires_in isKindOfClass:[NSString class]] )
            {
                NSNumberFormatter *formatter = [[NSNumberFormatter alloc] init];
                
                expires = [NSDate dateWithTimeIntervalSinceNow:[formatter numberFromString:expires_in].longValue];
            }
            else if ( [expires_in isKindOfClass:[NSNumber class]] )
            {
                expires = [NSDate dateWithTimeIntervalSinceNow:((NSNumber *)expires_in).longValue];
            }
            else
            {
                AD_LOG_WARN_F(@"Unparsable time", @"The response value for the access token expiration cannot be parsed: %@", expires);
                // Unparseable, use default value
                expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//1 hour
            }
        }
        else
        {
            AD_LOG_WARN(@"Missing expiration time.", @"The server did not return the expiration time for the access token.");
            expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//Assume 1hr expiration
        }
        
        item.accessTokenType = [response objectForKey:OAUTH2_TOKEN_TYPE];
        item.expiresOn       = expires;
        [ADLogger logToken:accessToken tokenType:@"access token" expiresOn:expires correlationId:responseUUID];
        
        if([response objectForKey:OAUTH2_REFRESH_TOKEN]){
            item.refreshToken    = [response objectForKey:OAUTH2_REFRESH_TOKEN];
        }
        
        NSString* resource   = [response objectForKey:OAUTH2_RESOURCE];
        BOOL multiResourceRefreshToken = NO;
        if (![NSString adIsStringNilOrBlank:resource])
        {
            if (item.resource && ![item.resource isEqualToString:resource])
            {
                AD_LOG_WARN_F(@"Wrong resource returned by the server.", @"Expected resource: '%@'; Server returned: '%@'", item.resource, resource);
            }
            //Currently, if the server has returned a "resource" parameter and we have a refresh token,
            //this token is a multi-resource refresh token:
            multiResourceRefreshToken = ![NSString adIsStringNilOrBlank:item.refreshToken];
        }
        [ADLogger logToken:item.refreshToken
                 tokenType:multiResourceRefreshToken ? @"multi-resource refresh token": @"refresh token"
                 expiresOn:nil
             correlationId:responseUUID];
        
        NSString* idToken = [response objectForKey:OAUTH2_ID_TOKEN];
        if (idToken)
        {
            ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:idToken error:nil];
            if (userInfo)
            {
                item.userInformation = userInfo;
            }
        }
        
        return [ADAuthenticationResult resultFromTokenCacheStoreItem:item multiResourceRefreshToken:multiResourceRefreshToken];
    }
    
    //No access token and no error, we assume that there was another kind of error (connection, server down, etc.).
    //Note that for security reasons we log only the keys, not the values returned by the user:
    NSString* errorMessage = [NSString stringWithFormat:@"The server returned without providing an error. Keys returned: %@", [response allKeys]];
    error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION
                                                   protocolCode:nil
                                                   errorDetails:errorMessage];
    return [ADAuthenticationResult resultFromError:error];
}

//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult*)result
                  cacheItem:(ADTokenCacheStoreItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
{
    [self updateCacheToResult:result
                cacheInstance:self.tokenCacheStore
                    cacheItem:cacheItem
             withRefreshToken:refreshToken];
}

- (void)updateCacheToResult:(ADAuthenticationResult*)result
              cacheInstance:(id<ADTokenCacheStoring>)tokenCacheStoreInstance
                  cacheItem:(ADTokenCacheStoreItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
{
    if(![ADAuthenticationContext handleNilOrEmptyAsResult:result argumentName:@"result" authenticationResult:&result]){
        return;
    }
    
    if (!tokenCacheStoreInstance)
        return;//No cache to update
    
    if (AD_SUCCEEDED == result.status)
    {
        if(![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheStoreItem argumentName:@"tokenCacheStoreItem" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheStoreItem.resource argumentName:@"resource" authenticationResult:&result]
           || ![ADAuthenticationContext handleNilOrEmptyAsResult:result.tokenCacheStoreItem.accessToken argumentName:@"accessToken" authenticationResult:&result])
        {
            return;
        }
        
        //In case of success we use explicitly the item that comes back in the result:
        cacheItem = result.tokenCacheStoreItem;
        NSString* savedRefreshToken = cacheItem.refreshToken;
        if (result.multiResourceRefreshToken)
        {
            AD_LOG_VERBOSE_F(@"Token cache store", @"Storing multi-resource refresh token for authority: %@", self.authority);
            
            //If the server returned a multi-resource refresh token, we break
            //the item into two: one with the access token and no refresh token and
            //another one with the broad refresh token and no access token and no resource.
            //This breaking is useful for further updates on the cache and quick lookups
            ADTokenCacheStoreItem* multiRefreshTokenItem = [cacheItem copy];
            cacheItem.refreshToken = nil;
            
            multiRefreshTokenItem.accessToken = nil;
            multiRefreshTokenItem.resource = nil;
            multiRefreshTokenItem.expiresOn = nil;
            [tokenCacheStoreInstance addOrUpdateItem:multiRefreshTokenItem error:nil];
        }
        
        AD_LOG_VERBOSE_F(@"Token cache store", @"Storing access token for resource: %@", cacheItem.resource);
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
            //The refresh token didn't work. We need to clear this refresh item from the cache.
            ADTokenCacheStoreKey* exactKey = [cacheItem extractKeyWithError:nil];
            if (exactKey)
            {
                ADTokenCacheStoreItem* existing = [tokenCacheStoreInstance getItemWithKey:exactKey userId:cacheItem.userInformation.userId error:nil];
                if ([refreshToken isEqualToString:existing.refreshToken])//If still there, attempt to remove
                {
                    AD_LOG_VERBOSE_F(@"Token cache store", @"Removing cache for resource: %@", cacheItem.resource);
                    [tokenCacheStoreInstance removeItemWithKey:exactKey userId:existing.userInformation.userId error:nil];
                    removed = YES;
                }
            }
            
            if (!removed)
            {
                //Now try finding a broad refresh token in the cache and remove it accordingly
                ADTokenCacheStoreKey* broadKey = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:nil clientId:cacheItem.clientId error:nil];
                if (broadKey)
                {
                    ADTokenCacheStoreItem* broadItem = [tokenCacheStoreInstance getItemWithKey:broadKey userId:cacheItem.userInformation.userId error:nil];
                    if (broadItem && [refreshToken isEqualToString:broadItem.refreshToken])//Remove if still there
                    {
                        AD_LOG_VERBOSE_F(@"Token cache store", @"Removing multi-resource refresh token for authority: %@", self.authority);
                        [tokenCacheStoreInstance removeItemWithKey:broadKey userId:cacheItem.userInformation.userId error:nil];
                    }
                }
            }
        }
    }
}

@end

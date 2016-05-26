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
#import "ADInstanceDiscovery.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "NSSet+ADExtensions.h"

@implementation ADAuthenticationRequest (AcquireAssertion)

- (void)acquireTokenForAssertion:(NSString*)samlAssertion
                   assertionType:(ADAssertionType)assertionType
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(samlAssertion);
    [self ensureRequest];

    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority
                                              correlationId:_correlationId
                                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         //Error should always be raised if the authority cannot be validated
#pragma unused(validated)
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error]);
         }
         else
         {
             [self validatedAcquireTokenForAssertion:samlAssertion
                                       assertionType:assertionType
                                     completionBlock:completionBlock];
         }
     }];
    return;//The asynchronous handler above will do the work.
}

- (void)validatedAcquireTokenForAssertion:(NSString*)samlAssertion
                            assertionType:(ADAssertionType)assertionType
                          completionBlock:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    //Check the cache:
    ADAuthenticationError* error = nil;
    
    //We are explicitly creating a key first to ensure indirectly that all of the required arguments are correct.
    //This is the safest way to guarantee it, it will raise an error, if the the any argument is not correct:
    ADTokenCacheStoreKey* key = [self cacheStoreKey:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    if ([_context hasCacheStore])
    {
        //Cache should be used in this case:
        BOOL tokenUsable;
        ADTokenCacheStoreItem* cacheItem = [_context findCacheItemWithKey:key
                                                                   userId:_identifier
                                                           useToken:&tokenUsable
                                                                    error:&error];
        if (error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error]);
            return;
        }
        
        if (cacheItem)
        {
            //Found a promising item in the cache, try using it:
            [self attemptToUseCacheItem:cacheItem
                         useToken:tokenUsable
                          samlAssertion:samlAssertion
                          assertionType:assertionType
                        completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
    }
    
    [self requestTokenByAssertion:samlAssertion
                    assertionType:assertionType
                       completion:completionBlock];
}

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheStoreItem*)item
               useToken:(BOOL)useToken
                samlAssertion:(NSString*)samlAssertion
                assertionType:(ADAssertionType)assertionType
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(item);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    [self ensureRequest];
    
    if (useToken)
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.token tokenType:@"oken" expiresOn:item.expiresOn correlationId:nil];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheStoreItem:item];
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
    [self acquireTokenByRefreshToken:item.refreshToken
                           cacheItem:item
                     completionBlock:^(ADAuthenticationResult *result)
     {
         //Asynchronous block:
         if ([ADAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestTokenByAssertion:samlAssertion
                         assertionType:assertionType
                            completion:completionBlock];
     }];//End of the refreshing token completion block, executed asynchronously.
}

- (NSString*) getAssertionTypeGrantValue:(ADAssertionType) assertionType
{
    if(assertionType == AD_SAML1_1){
        return OAUTH2_SAML11_BEARER_VALUE;
    }
    
    if(assertionType == AD_SAML2){
        return OAUTH2_SAML2_BEARER_VALUE;
    }
    
    return nil;
}

// Generic OAuth2 Authorization Request, obtains a token from a SAML assertion.
- (void)requestTokenByAssertion:(NSString *)samlAssertion
                  assertionType:(ADAssertionType)assertionType
                     completion:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", @"Requesting token by authorization code with scopes: %@", _scopes);
    
    //samlAssertion = [NSString samlAssertion adBase64];
    NSData *encodeData = [samlAssertion dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [encodeData base64EncodedStringWithOptions:0];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         [self getAssertionTypeGrantValue:assertionType], OAUTH2_GRANT_TYPE,
                                         base64String, OAUTH2_ASSERTION,
                                         _clientId, OAUTH2_CLIENT_ID,
                                         [self.combinedScopes adSpaceDeliminatedString], OAUTH2_SCOPE,
                                         nil];
    
    if (_policy)
    {
        [request_data setObject:_policy forKey:OAUTH2_POLICY];
    }
    
    [self executeRequest:_context.authority
             requestData:request_data
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}

@end

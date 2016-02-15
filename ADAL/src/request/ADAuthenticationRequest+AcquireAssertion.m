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
#import "ADInstanceDiscovery.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"

@implementation ADAuthenticationRequest (AcquireAssertion)

- (void)acquireTokenForAssertion:(NSString*)samlAssertion
                   assertionType:(ADAssertionType)assertionType
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_PROPERTY(_resource);
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
             completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
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
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:_context.authority
                                                              resource:_resource
                                                              clientId:_clientId error:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:_correlationId];
        completionBlock(result);
        return;
    }
    
    if ([_context hasCacheStore])
    {
        //Cache should be used in this case:
        ADTokenCacheItem* cacheItem = [_context findCacheItemWithKey:key
                                                              userId:_identifier
                                                       correlationId:_correlationId
                                                               error:&error];
        if (error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
            return;
        }
        
        if (cacheItem)
        {
            //Found a promising item in the cache, try using it:
            [self attemptToUseCacheItem:cacheItem
                          samlAssertion:samlAssertion
                          assertionType:assertionType
                        completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
    }
    
    [self requestTokenByAssertion:samlAssertion
                    assertionType:assertionType
                       completion:^(ADAuthenticationResult* result)
    {
        if (result.status == AD_SUCCEEDED)
        {
            [_context updateCacheToResult:result cacheItem:nil withRefreshToken:nil requestCorrelationId:_correlationId];
        }
        
        completionBlock(result);
    }];
}

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheItem*)item
                samlAssertion:(NSString*)samlAssertion
                assertionType:(ADAssertionType)assertionType
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(item, _correlationId);
    AD_REQUEST_CHECK_PROPERTY(_resource);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    [self ensureRequest];
    
    if (item.accessToken && !item.isExpired)
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:_correlationId];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheItem:item multiResourceRefreshToken:NO correlationId:_correlationId];
        completionBlock(result);
        return;
    }
    
    if ([NSString adIsStringNilOrBlank:item.refreshToken])
    {
        completionBlock([ADAuthenticationResult resultFromError:[ADAuthenticationError unexpectedInternalError:@"Attempting to use an item without refresh token." correlationId:_correlationId]
                                                  correlationId:_correlationId]);
        return;
    }
    
    //Now attempt to use the refresh token of the passed cache item:
    BOOL isMultiresourceRefreshToken = [item isMultiResourceRefreshToken];
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
         
         //Try other means of getting access token result:
         if (!isMultiresourceRefreshToken)//Try multi-resource refresh token if not currently trying it
         {
             ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:_context.authority resource:nil clientId:_clientId error:nil];
             if (broadKey)
             {
                 ADAuthenticationError* error = nil;
                 ADTokenCacheItem* broadItem = [_context findCacheItemWithKey:broadKey userId:_identifier correlationId:_correlationId error:&error];
                 if (error)
                 {
                     completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
                     return;
                 }
                 
                 if (broadItem)
                 {
                     if (![broadItem isMultiResourceRefreshToken])
                     {
                         AD_LOG_WARN(@"Unexpected", _correlationId, @"Multi-resource refresh token expected here.");
                         //Recover (avoid infinite recursion):
                         completionBlock(result);
                         return;
                     }
                     
                     //Call recursively with the cache item containing a multi-resource refresh token:
                     [self attemptToUseCacheItem:broadItem
                                   samlAssertion:samlAssertion
                                   assertionType:assertionType
                                 completionBlock:completionBlock];
                     return;//The call above takes over, no more processing
                 }//broad item
             }//key
         }//!item.multiResourceRefreshToken
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestTokenByAssertion:samlAssertion
                         assertionType:assertionType
                            completion:^(ADAuthenticationResult *result)
          {
              if (result.status == AD_SUCCEEDED)
              {
                  [_context updateCacheToResult:result cacheItem:nil withRefreshToken:nil requestCorrelationId:_correlationId];
              }
              
              completionBlock(result);
          }];
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
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", _correlationId, @"Requesting token by authorization code for resource: %@", _resource);
    
    //samlAssertion = [NSString samlAssertion adBase64];
    NSData *encodeData = [samlAssertion dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [encodeData base64EncodedStringWithOptions:0];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         [self getAssertionTypeGrantValue:assertionType], OAUTH2_GRANT_TYPE,
                                         base64String, OAUTH2_ASSERTION,
                                         _clientId, OAUTH2_CLIENT_ID,
                                         _resource, OAUTH2_RESOURCE,
                                         OAUTH2_SCOPE_OPENID_VALUE, OAUTH2_SCOPE,
                                         nil];
    [self executeRequest:_context.authority
             requestData:request_data
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}

@end

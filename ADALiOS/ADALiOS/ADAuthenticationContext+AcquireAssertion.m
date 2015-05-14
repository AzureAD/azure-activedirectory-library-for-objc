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

@implementation ADAuthenticationContext (AcquireAssertion)

- (void)internalAcquireTokenForAssertion:(NSString*)samlAssertion
                                clientId:(NSString*)clientId
                             redirectUri:(NSString*)redirectUri
                                resource:(NSString*)resource
                           assertionType:(ADAssertionType)assertionType
                                  userId:(NSString*)userId
                                   scope:(NSString*)scope
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(resource);
    HANDLE_ARGUMENT(samlAssertion);
    
    [self updateCorrelationId:&correlationId];
    
    if (validateAuthority)
    {
        [[ADInstanceDiscovery sharedInstance] validateAuthority:self.authority correlationId:correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
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
                                                clientId:clientId
                                             redirectUri:redirectUri
                                                resource:resource
                                           assertionType: assertionType
                                                  userId:userId
                                                   scope:scope
                                           correlationId:correlationId
                                         completionBlock:completionBlock];
             }
         }];
        return;//The asynchronous handler above will do the work.
    }
    
    [self validatedAcquireTokenForAssertion:samlAssertion
                                   clientId:clientId
                                redirectUri:redirectUri
                                   resource:resource
                              assertionType: assertionType
                                     userId:userId
                                      scope:scope
                              correlationId:correlationId
                            completionBlock:completionBlock];
}

- (void) validatedAcquireTokenForAssertion: (NSString*) samlAssertion
                                  clientId: (NSString*) clientId
                               redirectUri: (NSString*) redirectUri
                                  resource: (NSString*) resource
                             assertionType: (ADAssertionType) assertionType
                                    userId: (NSString*) userId
                                     scope: (NSString*) scope
                             correlationId: (NSUUID*) correlationId
                           completionBlock: (ADAuthenticationCallback)completionBlock
{
    //Check the cache:
    ADAuthenticationError* error = nil;
    //We are explicitly creating a key first to ensure indirectly that all of the required arguments are correct.
    //This is the safest way to guarantee it, it will raise an error, if the the any argument is not correct:
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:resource clientId:clientId error:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    if (self.tokenCacheStore)
    {
        //Cache should be used in this case:
        BOOL accessTokenUsable;
        ADTokenCacheStoreItem* cacheItem = [self findCacheItemWithKey:key userId:userId useAccessToken:&accessTokenUsable error:&error];
        if (error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error]);
            return;
        }
        
        if (cacheItem)
        {
            //Found a promising item in the cache, try using it:
            [self attemptToUseCacheItem:cacheItem
                         useAccessToken:accessTokenUsable
                          samlAssertion:samlAssertion
                          assertionType:assertionType
                               resource:resource
                               clientId:clientId
                            redirectUri:redirectUri
                                 userId:userId
                          correlationId:correlationId
                        completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
    }
    
    [self requestTokenByAssertion: samlAssertion
                    assertionType: assertionType
                         resource: resource
                         clientId: clientId
                            scope: nil//For future use
                    correlationId: correlationId
                       completion: completionBlock];
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
                       resource:(NSString *)resource
                       clientId:(NSString*)clientId
                          scope:(NSString*)scope //For future use
                  correlationId:(NSUUID*)correlationId
                     completion:(ADAuthenticationCallback)completionBlock
{
#pragma unused(scope)
    HANDLE_ARGUMENT(correlationId);//Should be set by the caller
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", @"Requesting token by authorization code for resource: %@", resource);
    
    //samlAssertion = [NSString samlAssertion adBase64];
    NSData *encodeData = [samlAssertion dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [encodeData base64EncodedStringWithOptions:0];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         [self getAssertionTypeGrantValue:assertionType], OAUTH2_GRANT_TYPE,
                                         base64String, OAUTH2_ASSERTION,
                                         clientId, OAUTH2_CLIENT_ID,
                                         resource, OAUTH2_RESOURCE,
                                         nil];
    [self executeRequest:self.authority
             requestData:request_data
                resource:resource
                clientId:clientId
    requestCorrelationId:correlationId
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}

@end

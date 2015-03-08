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

#import "ADBrokerPRTContext.h"
#import "ADBrokerConstants.h"
#import "ADBrokerJwtHelper.h"
#import "ADBrokerPRTCacheItem.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import "NSString+ADBrokerHelperMethods.h"
#import <workplaceJoinAPI/WorkPlaceJoin.h>
#import "ADAuthenticationBroker.h"

@implementation ADBrokerPRTContext

ADAuthenticationContextForBroker* ctx;
NSString* userPrincipalIdentifier;

-(id) initWithUpn:(NSString*) upn
    correlationId:(NSUUID*) correlationId
            error: (ADAuthenticationError* __autoreleasing *) error
{
    self = [super init];
    
    if(self)
    {
        ADAuthenticationError* error = nil;
        ctx = [[ADAuthenticationContextForBroker alloc] initWithAuthority:DEFAULT_AUTHORITY
                                                        validateAuthority:YES
                                                          tokenCacheStore:[[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL]
                                                                    error:&error];
        [ctx setCorrelationId:correlationId];
        if(!error)
        {
            userPrincipalIdentifier = upn;
            return self;
        }
    }
    
    return nil;
}

-(void) deletePRT
{
    ADAuthenticationError* error = nil;
    //get PRT from cache
    id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL];
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:DEFAULT_GUID_FOR_NIL
                                                              resource:nil
                                                              clientId:DEFAULT_GUID_FOR_NIL
                                                                 error:&error];
    //TODO figure out error case
    [cacheStore removeItemWithKey:key
                           userId:userPrincipalIdentifier
                            error:&error];
}

-(void) acquirePRTForUPN: (ADPRTResultCallback)callback
{
    ADAuthenticationError* error = nil;
    //get PRT from cache
    id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL];
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:DEFAULT_GUID_FOR_NIL
                                                              resource:nil
                                                              clientId:DEFAULT_GUID_FOR_NIL
                                                                 error:&error];
    ADBrokerPRTCacheItem* item = (ADBrokerPRTCacheItem*)[cacheStore getItemWithKey:key
                                                                            userId:userPrincipalIdentifier
                                                                             error:&error];
    if(!error && item)
    {
        callback(item, error);
        return;
    }
    
    // get broker client ID token
    [ctx acquireTokenWithResource: BROKER_RESOURCE
                         clientId: BROKER_CLIENT_ID
                      redirectUri: [NSURL URLWithString:BROKER_REDIRECT_URI]
                           userId: userPrincipalIdentifier
                            scope: @"openid aza"
             extraQueryParameters: @"nux=1"
                  completionBlock:^(ADAuthenticationResult *result) {
                      ADAuthenticationError* error;
                      if(result.status == AD_SUCCEEDED)
                      {
                          ADTokenCacheStoreKey* key = [result.tokenCacheStoreItem extractKeyWithError:&error];
                          if(error)
                          {
                              callback(nil, error);
                              return;
                          }else{
                              // we have a fresh AT and RT. Get RT from cache as it is not returned
                              // in the result.
                              NSArray* items = [ctx.tokenCacheStore getItemsWithKey:key
                                                                              error:&error];
                              NSString* brokerRefreshToken = nil;
                              for(ADTokenCacheStoreItem* item in items)
                              {
                                  if (item.refreshToken
                                      && item.userInformation
                                      && [NSString adSame:userPrincipalIdentifier
                                                 toString:item.userInformation.upn] && !item.isExpired)
                                  {
                                      brokerRefreshToken = item.refreshToken;
                                      break;
                                  }
                              }
                              //use the RT to get PRT
                              //create JWT
                              NSString* jwtToken = [self createPRTRequestJWTUsingBrokerRT:brokerRefreshToken];
                              NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                                   @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE_KEY,
                                                                   jwtToken, @"request",
                                                                   nil];
                              
                              //send JWT to token endpoint
                              [ctx request:DEFAULT_AUTHORITY
                               requestData:request_data
                      requestCorrelationId:[ctx getCorrelationId]
               isHandlingPKeyAuthChallenge:NO
                         additionalHeaders:request_data
                                completion:^(NSDictionary *response) {
                                    
                                    ADBrokerPRTCacheItem* item = [ADBrokerPRTCacheItem new];
                                    item.userInformation = nil;
                                    item.clientId = DEFAULT_GUID_FOR_NIL;
                                    
                                    //create result for PRT and populate cache item object
                                    ADAuthenticationResult* prtResult = [self processPRTResponse:response
                                                                                         forItem:item
                                                                                     fromRefresh:NO
                                                                            requestCorrelationId:[ctx getCorrelationId]];
                                    if(prtResult.status == AD_SUCCEEDED)
                                    {
                                        ADAuthenticationError* error;
                                        //persist PRT cache item
                                        [ctx.tokenCacheStore addOrUpdateItem:item
                                                                       error:&error];
                                        callback(item, error);
                                    }
                                    else
                                    {
                                        callback(nil, prtResult.error);
                                    }
                                }];
                          }
                          
                      }else{
                          //failed to get token for broker client id.
                          callback(nil, result.error);
                      }
                  }];
}


/*! Gets token for a client Id using PRT. If expired, the PRT is refreshed via webview.*/
-(void) acquireTokenUsingPRTForResource:(NSString*) resource
                               clientId:(NSString*) clientId
                            redirectUri:(NSString*) redirectUri
                                 appKey:(NSString*) appKey
                        completionBlock:(ADAuthenticationCallback) completionBlock
{
    [self acquireTokenUsingPRTForResource:resource
                                 clientId:clientId
                              redirectUri:redirectUri
                                   appKey:appKey
                         attemptPRTUpdate:YES
                          completionBlock:completionBlock];
}


/*! Gets token for a client Id using PRT. If expired, the PRT is refreshed via webview.*/
-(void) acquireTokenUsingPRTForResource:(NSString*) resource
                               clientId:(NSString*) clientId
                            redirectUri:(NSString*) redirectUri
                                 appKey:(NSString*) appKey
                       attemptPRTUpdate:(BOOL)attemptPRTUpdate
                        completionBlock:(ADAuthenticationCallback) completionBlock
{
    
    [self acquirePRTForUPN:^(ADBrokerPRTCacheItem *prtItem, NSError *error) {
        
        if(!error)
        {
            // found PRT token. Use it against token endpoint
            
            //create JWT
            NSString* jwtToken = [self createAccessTokenRequestJWTUsingPRT:prtItem
                                                                  resource:resource
                                                                  clientId:clientId];
            NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                 @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE_KEY,
                                                 jwtToken, @"request",
                                                 nil];
            
            //send JWT to token endpoint
            [ctx request:DEFAULT_AUTHORITY
             requestData:request_data
    requestCorrelationId:[ctx getCorrelationId]
isHandlingPKeyAuthChallenge:NO
       additionalHeaders:nil
              completion:^(NSDictionary *response) {
                  
                  ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
                  item.resource = resource;
                  item.clientId = clientId;
                  ADAuthenticationResult* result = [ctx processTokenResponse:response
                                                                     forItem:item
                                                                 fromRefresh:NO
                                                        requestCorrelationId:[ctx getCorrelationId]];
                  
                  if(result.status == AD_SUCCEEDED)
                  {
                      //save AT and RT in the app key specific cache
                      id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:appKey];
                      [ctx updateCacheToResult:result
                                 cacheInstance:cacheStore
                                     cacheItem:nil
                              withRefreshToken:nil];
                      result = [ctx updateResult:result
                                          toUser:userPrincipalIdentifier];
                  } else{
                      if(attemptPRTUpdate)
                      {
                          NSString* errorType = [response objectForKey:OAUTH2_ERROR_KEY];
                          if(errorType && [NSString adSame:errorType toString:@"interaction_required"])
                          {
                              // if error is interaction_required use webview
                              [self acquireTokenViaWebviewInteractionForResource:resource
                                                                        clientId:clientId
                                                                     redirectUri:redirectUri
                                                                          appKey:appKey
                                                                         prtItem:prtItem
                                                                 completionBlock:completionBlock];
                          }
                          else
                          {
                              // remove PRT from cache
                              [self deletePRT];
                              
                              // call acquireTokenUsingPRTForResource recursively with
                              // attemptPRTUpdate=NO to avoid infinite recursion.
                              [self acquireTokenUsingPRTForResource:resource
                                                           clientId:clientId
                                                        redirectUri:redirectUri
                                                             appKey:appKey
                                                   attemptPRTUpdate:NO
                                                    completionBlock:completionBlock];
                          }
                          return;
                      }
                  }
                  completionBlock(result);
              }];
        }
        else
        {
            //could not get PRT.
            //TODO log error and call adal with appkey specific cache.
            ADAuthenticationError* authError;
            ADAuthenticationContextForBroker* adalContext = [[ADAuthenticationContextForBroker alloc] initWithAuthority:DEFAULT_AUTHORITY
                                                                                                      validateAuthority:YES
                                                                                                        tokenCacheStore:[[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:appKey]
                                                                                                                  error:&authError];
            adalContext.correlationId = ctx.correlationId;
            if(error)
            {
                completionBlock([ADAuthenticationResult resultFromError:authError]);
            }
            else
            {
                [adalContext acquireTokenWithResource:resource
                                             clientId:clientId
                                          redirectUri:[NSURL URLWithString:redirectUri]
                                               userId:userPrincipalIdentifier
                                 extraQueryParameters:@"nux=1"
                                      completionBlock:completionBlock];
            }
        }
    }];
}

- (void)acquireTokenViaWebviewInteractionForResource:(NSString*) resource
                                            clientId:(NSString*) clientId
                                         redirectUri:(NSString*) redirectUri
                                              appKey:(NSString*) appKey
                                             prtItem:(ADBrokerPRTCacheItem*) prtItem
                                     completionBlock:(ADAuthenticationCallback) completionBlock
{
    [ctx requestCodeByResource:resource
                      clientId:clientId
                   redirectUri:[NSURL URLWithString:redirectUri]
                         scope:nil
                        userId:userPrincipalIdentifier
                promptBehavior:AD_PROMPT_AUTO extraQueryParameters:@"nux=1"
                 correlationId:ctx.getCorrelationId
                    completion:^(NSString *code, ADAuthenticationError *authError) {
        if(!authError)
        {
            
        }
        else
        {
            //create JWT
            NSString* jwtToken = [self createAccessTokenRequestJWTUsingPRT:prtItem
                                                                  resource:resource
                                                                  clientId:clientId];
            NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                 @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE_KEY,
                                                 jwtToken, @"request",
                                                 nil];
            
            //send JWT to token endpoint
            [ctx request:DEFAULT_AUTHORITY
             requestData:request_data
    requestCorrelationId:[ctx getCorrelationId]
isHandlingPKeyAuthChallenge:NO
       additionalHeaders:nil
              completion:^(NSDictionary *response) {
                  
                  ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
                  item.resource = resource;
                  item.clientId = clientId;
                  ADAuthenticationResult* result = [ctx processTokenResponse:response
                                                                     forItem:item
                                                                 fromRefresh:NO
                                                        requestCorrelationId:[ctx getCorrelationId]];
                  
                  if(result.status == AD_SUCCEEDED)
                  {
                      //save AT and RT in the app key specific cache
                      id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:appKey];
                      [ctx updateCacheToResult:result
                                 cacheInstance:cacheStore
                                     cacheItem:nil
                              withRefreshToken:nil];
                      result = [ctx updateResult:result
                                          toUser:userPrincipalIdentifier];
                  }
                  completionBlock(result);
              }];
        }
    }];
}




-(NSString*) createAccessTokenRequestJWTUsingPRT:(ADBrokerPRTCacheItem*) item
                                        resource:(NSString*) resource
                                        clientId:(NSString*) clientId
{
    NSError* error;
    RegistrationInformation* identity = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:&error];
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"kid" : [item sessionKey],
                             @"ctx" : ctx
                             };
    NSDictionary *payload = @{
                              @"version" : @"2",
                              @"resource" : resource,
                              @"client_id" : clientId,
                              @"refresh_token" : [item refreshToken],
                              @"iss" : @"aad:brokerplugin",
                              @"iat" : [NSString stringWithFormat:@"%d", (CC_LONG)[[NSDate date] timeIntervalSince1970]],
                              @"scope" : @"openid aza",
                              @"grant_type" : @"refresh_token",
                              @"aud" : DEFAULT_AUTHORITY
                              };
    
    NSString* returnValue = [ADBrokerJwtHelper createSignedJWTforHeader:header
                                                                payload:payload
                                                             signingKey:[identity sessionTransportPrivateKey]];
    [identity releaseData];
    return returnValue;
}


-(NSString*) createPRTRequestJWTUsingBrokerRT:(NSString*) brokerRefreshToken
{
    NSError* error;
    RegistrationInformation* identity = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:&error];
    NSArray *arrayOfStrings = @[[NSString stringWithFormat:@"%@", [[identity certificateData] base64EncodedStringWithOptions:0]]];
    NSDictionary *header = @{
                             @"alg" : @"RS256",
                             @"typ" : @"JWT",
                             @"x5c" : arrayOfStrings
                             };
    NSDictionary *payload = @{
                              @"refresh_token" : brokerRefreshToken,
                              @"client_id" : BROKER_CLIENT_ID,
                              @"scope" : @"openid aza",
                              @"grant_type" : @"refresh_token"
                              };
    
    return [ADBrokerJwtHelper createSignedJWTforHeader:header
                                               payload:payload
                                            signingKey:[identity sessionTransportPrivateKey]];
}




//Understands and processes the access token response:
- (ADAuthenticationResult *) processPRTResponse: (NSDictionary *)response
                                        forItem: (ADBrokerPRTCacheItem*)item
                                    fromRefresh: (BOOL) fromRefreshTokenWorkflow
                           requestCorrelationId: (NSUUID*) requestCorrelationId
{
    THROW_ON_NIL_ARGUMENT(response);
    THROW_ON_NIL_ARGUMENT(item);
    AD_LOG_VERBOSE(@"Token extraction", @"Attempt to extract the data from the server response.");
    
    NSString* responseId = [response objectForKey:CORRELATION_ID_RESPONSE];
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
    
    ADAuthenticationError* error = [ctx errorFromDictionary:response errorCode:(fromRefreshTokenWorkflow) ? AD_ERROR_INVALID_REFRESH_TOKEN : AD_ERROR_AUTHENTICATION];
    if (error)
    {
        return [ADAuthenticationResult resultFromError:error];
    }
    
    NSString* refreshToken = [response objectForKey:OAUTH2_REFRESH_TOKEN_KEY];
    if (![NSString adIsStringNilOrBlank:refreshToken])
    {
        item.refreshToken    = refreshToken;
        item.authority = DEFAULT_GUID_FOR_NIL;
        
        // Token response
        id      expires_in = [response objectForKey:OAUTH2_REFRESH_TOKEN_EXPIRES_KEY];
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
        
        item.tokenType = [response objectForKey:OAUTH2_TOKEN_TYPE_KEY];
        item.expiresOn       = expires;
        //        [ADLogger logToken:accessToken tokenType:@"access token" expiresOn:expires correlationId:responseUUID];
        //
        
        //        [ADLogger logToken:item.refreshToken
        //                 tokenType:multiResourceRefreshToken ? @"multi-resource refresh token": @"refresh token"
        //                 expiresOn:nil
        //             correlationId:responseUUID];
        
        NSString* idToken = [response objectForKey:OAUTH2_ID_TOKEN_KEY];
        if (idToken)
        {
            ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:idToken error:nil];
            if (userInfo)
            {
                item.userInformation = userInfo;
            }
        }
        
        return [ADAuthenticationResult resultFromTokenCacheStoreItem:item multiResourceRefreshToken:NO];
    }
    
    //No refresh token and no error, we assume that there was another kind of error (connection, server down, etc.).
    //Note that for security reasons we log only the keys, not the values returned by the user:
    NSString* errorMessage = [NSString stringWithFormat:@"The server returned without providing an error. Keys returned: %@", [response allKeys]];
    error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION
                                                   protocolCode:nil
                                                   errorDetails:errorMessage];
    return [ADAuthenticationResult resultFromError:error];
}

@end

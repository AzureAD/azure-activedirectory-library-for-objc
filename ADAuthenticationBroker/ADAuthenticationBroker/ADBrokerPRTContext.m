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


#import "ADOAuth2Constants.h"
#import "NSString+ADHelperMethods.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADBrokerPRTContext.h"
#import "ADBrokerConstants.h"
#import "ADBrokerJwtHelper.h"
#import "ADBrokerPRTCacheItem.h"
#import "ADBrokerBase64Additions.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import <workplaceJoinAPI/WorkPlaceJoin.h>
#import "ADBrokerJWEResponse.h"
#import "ADBrokerHelpers.h"
#import "ADBrokerSettings.h"

#import "ADAuthenticationContext+BrokerSDK.h"

@implementation ADBrokerPRTContext
{
    ADAuthenticationContext* _ctx;
    NSString* _userPrincipalIdentifier;
    NSString* _authority;
}

- (id)initWithUpn:(NSString*)upn
        authority:(NSString*)authority
    correlationId:(NSUUID*)correlationId
            error:(ADAuthenticationError* __autoreleasing *)error
{
    ADAuthenticationContext* ctx = nil;
    if (!authority)
    {
        authority = [ADBrokerSettings sharedInstance].authority;
    }
    
    ctx = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                           validateAuthority:YES
                                             tokenCacheStore:[[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL]
                                                       error:error];
    if (!ctx)
        return nil;
    
    [ctx setCorrelationId:correlationId];
    
    if (!(self = [super init]))
        return nil;
    
    _userPrincipalIdentifier = upn;
    _ctx = ctx;
    _authority = authority;

    return self;
}

- (void)deletePRT
{
    ADAuthenticationError* error = nil;
    //get PRT from cache
    id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL];
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:_authority
                                                              resource:nil
                                                              clientId:DEFAULT_GUID_FOR_NIL
                                                                 error:&error];
    //TODO figure out error case
    [cacheStore removeItemWithKey:key
                           userId:_userPrincipalIdentifier
                            error:&error];
    if(error)
    {
        AD_LOG_ERROR_F(@"PRT delete", error.code, @"failed to delete from keychain - %@", error.errorDetails);
    }
}

- (void)acquirePRTForUPN:(ADPRTResultCallback)callback
{
    ADAuthenticationError* error = nil;
    //get PRT from cache
    id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:DEFAULT_GUID_FOR_NIL];
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:_authority
                                                              resource:nil
                                                              clientId:DEFAULT_GUID_FOR_NIL
                                                                 error:&error];
    ADBrokerPRTCacheItem* item = (ADBrokerPRTCacheItem*)[cacheStore getItemWithKey:key
                                                                            userId:_userPrincipalIdentifier
                                                                             error:&error];
    if(!error && item && !item.isExpired)
    {
        AD_LOG_INFO(@"Valid PRT found in cache.", nil);
        
        //success
        callback(item, error);
        return;
    }
    
    AD_LOG_INFO(@"Valid PRT NOT found in cache... Acquiring new PRT", nil);
    // get broker client ID token
    [_ctx validatedAcquireTokenWithResource:[ADBrokerSettings sharedInstance].graphResourceEndpoint
                                  clientId:BROKER_CLIENT_ID
                               redirectUri:[NSURL URLWithString:BROKER_REDIRECT_URI]
                            promptBehavior:AD_PROMPT_AUTO
                                    silent:NO
                                    userId:_userPrincipalIdentifier
                                     scope:@"openid"
                      extraQueryParameters:@"nux=1"
                             correlationId:[_ctx getCorrelationId]
                           completionBlock:^(ADAuthenticationResult *result) {
                               ADAuthenticationError* error;
                               if(result.status == AD_SUCCEEDED)
                               {
                                   ADTokenCacheStoreKey* accessTokenKey = [result.tokenCacheStoreItem extractKeyWithError:nil];
                                   ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:accessTokenKey.authority
                                                                                             resource:nil
                                                                                             clientId:BROKER_CLIENT_ID
                                                                                                error:&error];
                                   if(error)
                                   {
                                       callback(nil, error);
                                       return;
                                   }else{
                                       // we have a fresh AT and RT. Get RT from cache as it is not returned
                                       // in the result.
                                       
                                       NSArray* items = [_ctx.tokenCacheStore getItemsWithKey:key
                                                                                       error:&error];
                                       NSString* brokerRefreshToken = nil;
                                       for(ADTokenCacheStoreItem* item in items)
                                       {
                                           if (item.refreshToken
                                               && item.userInformation
                                               && [NSString adSame:_userPrincipalIdentifier
                                                          toString:item.userInformation.upn] && !item.isExpired)
                                           {
                                               brokerRefreshToken = item.refreshToken;
                                               break;
                                           }
                                       }
                                       
                                       if(!brokerRefreshToken)
                                       {
                                           error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_REFRESH_TOKEN
                                                                                          protocolCode:nil errorDetails:@"NO Refresh token found for broker client id"];
                                           callback(nil, error);
                                           return;
                                       }
                                       
                                       //use the RT to get PRT
                                       //create JWT
                                       
                                       AD_LOG_INFO(@"Acquiring PRT using broker refresh token", nil);
                                       NSString* jwtToken = [self createPRTRequestJWTUsingBrokerRT:brokerRefreshToken];
                                       NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                                            @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE,
                                                                            jwtToken, @"request",
                                                                            nil];
                                       
                                       void (^prtProcessCallback)(NSDictionary *response) =  ^(NSDictionary *response) {
                                           
                                           ADBrokerPRTCacheItem* item = [ADBrokerPRTCacheItem new];
                                           item.userInformation = nil;
                                           item.clientId = DEFAULT_GUID_FOR_NIL;
                                           
                                           //create result for PRT and populate cache item object
                                           ADAuthenticationResult* prtResult = [self processPRTResponse:response
                                                                                                forItem:item
                                                                                            fromRefresh:NO
                                                                                   requestCorrelationId:[_ctx getCorrelationId]];
                                           if(prtResult.status == AD_SUCCEEDED)
                                           {
                                               
                                               AD_LOG_INFO(@"Acquired PRT successfully", nil);
                                               ADAuthenticationError* err;
                                               //persist PRT cache item
                                               [_ctx.tokenCacheStore addOrUpdateItem:item
                                                                              error:&err];
                                               callback(item, err);
                                           }
                                           else
                                           {
                                               callback(nil, prtResult.error);
                                           }
                                       };
                                       
                                       //send JWT to token endpoint
                                       [_ctx requestWithServer:_authority
                                                  requestData:request_data
                                         requestCorrelationId:[_ctx getCorrelationId]
                                              handledPkeyAuth:NO
                                            additionalHeaders:request_data
                                            returnRawResponse:NO
                                                   completion:prtProcessCallback];
                                   }
                                   
                               }else{
                                   //failed to get token for broker client id.
                                   callback(nil, result.error);
                               }
                           }];
}


/*! Gets token for a client Id using PRT. If expired, the PRT is refreshed via webview.*/
- (void)acquireTokenUsingPRTForResource:(NSString*)resource
                               clientId:(NSString*)clientId
                            redirectUri:(NSString*)redirectUri
                                 appKey:(NSString*)appKey
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
- (void)acquireTokenUsingPRTForResource:(NSString*)resource
                               clientId:(NSString*)clientId
                            redirectUri:(NSString*)redirectUri
                                 appKey:(NSString*)appKey
                       attemptPRTUpdate:(BOOL)attemptPRTUpdate
                        completionBlock:(ADAuthenticationCallback) completionBlock
{
    
    [self acquirePRTForUPN:^(ADBrokerPRTCacheItem *prtItem, NSError *error)
     {
         if(!error)
         {
             // found PRT token. Use it against token endpoint
             //create JWT
             NSString* jwtToken = [self createAccessTokenRequestJWTUsingPRT:prtItem
                                                                   resource:resource
                                                                   clientId:clientId];
             NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                  redirectUri, @"redirect_uri",
                                                  clientId, @"client_id",
                                                  @"2.0", @"windows_api_version",
                                                  @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE,
                                                  jwtToken, @"request",
                                                  nil];
             
             //send JWT to token endpoint
             [_ctx requestWithServer:_authority
                        requestData:request_data
               requestCorrelationId:[_ctx getCorrelationId]
                    handledPkeyAuth:NO
                  additionalHeaders:nil
                  returnRawResponse:YES
                         completion:^(NSDictionary *response)
              {
                  
                  if([response valueForKey:@"raw_response"])
                  {
                      ADBrokerJWEResponse* jweResp = [[ADBrokerJWEResponse alloc] initWithRawJWE:[response valueForKey:@"raw_response"]];
                      response = [ADBrokerJwtHelper decryptJWEResponseUsingKeyDerivation:jweResp
                                                                                 context:[jweResp headerContext]
                                                                                     key:prtItem.sessionKey];
                      
                      //if id_token is not returned, Use id_token from PRT entry
                      if(![response valueForKey:OAUTH2_ID_TOKEN])
                      {
                          AD_LOG_INFO(@"id_token not returned with access token. Using PRT id_token instead.", nil);
                          [response setValue:[prtItem.userInformation rawIdToken]
                                      forKey:OAUTH2_ID_TOKEN];
                      }
                  }
                  
                  ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
                  item.resource = resource;
                  item.clientId = clientId;
                  ADAuthenticationResult* result = [_ctx processTokenResponse:response
                                                                     forItem:item
                                                                 fromRefresh:NO
                                                        requestCorrelationId:[_ctx getCorrelationId]];
                  
                  if(result.status == AD_SUCCEEDED)
                  {
                      //save AT and RT in the app key specific cache
                      id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:appKey];
                      [_ctx updateCacheToResult:result
                                 cacheInstance:cacheStore
                                     cacheItem:nil
                              withRefreshToken:nil];
                      result = [_ctx updateResult:result
                                          toUser:_userPrincipalIdentifier];
                  } else{
                      if(attemptPRTUpdate)
                      {
                          NSString* errorType = [response objectForKey:OAUTH2_ERROR];
                          if(errorType && ([NSString adSame:errorType toString:@"interaction_required"]))
                          {
                              dispatch_async(dispatch_get_main_queue(), ^
                                             {
                                                 // if error is interaction_required use webview
                                                 [self acquireTokenViaWebviewInteractionForResource:resource
                                                                                           clientId:clientId
                                                                                        redirectUri:redirectUri
                                                                                             appKey:appKey
                                                                                            prtItem:prtItem
                                                                                    completionBlock:completionBlock];
                                             });
                          }
                          else
                          {
                              
                              if(errorType && ([NSString adSame:errorType toString:@"invalid_grant"]))
                              {
                                  // remove PRT from cache
                                  [self deletePRT];
                                  
                                  // call acquireTokenUsingPRTForResource recursively with
                                  // attemptPRTUpdate=NO to avoid infinite recursion.
                                  //TODO wait for a little bit?
                                  [self acquireTokenUsingPRTForResource:resource
                                                               clientId:clientId
                                                            redirectUri:redirectUri
                                                                 appKey:appKey
                                                       attemptPRTUpdate:NO
                                                        completionBlock:completionBlock];
                              }
                              else
                              {
                                  completionBlock(result);
                              }
                          }
                          return;
                      }
                  }
                  completionBlock(result);
              }];
         }
         else
         {
             //could not get PRT. bubble up the error to calling app.
             completionBlock([ADAuthenticationResult resultFromError:[ADAuthenticationError errorFromNSError:error errorDetails:error.description]]);
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
    API_ENTRY;
    
    NSString* refreshTokenCredential = [self createRefreshTokenCredentialJWT:prtItem];
    
    [_ctx requestCodeByResource: resource
                      clientId: clientId
                   redirectUri: [NSURL URLWithString:redirectUri]
                         scope: @"openid"
                        userId: _userPrincipalIdentifier
                promptBehavior: AD_PROMPT_AUTO
          extraQueryParameters: @"nux=1"
        refreshTokenCredential: refreshTokenCredential
                 correlationId: _ctx.getCorrelationId
                    completion:^(NSString *code, ADAuthenticationError *authError) {
                        if(authError)
                        {
                            completionBlock([ADAuthenticationResult resultFromError:authError]);
                        }
                        else
                        {
                            //create JWT
                            NSString* jwtToken = [self createPRTRequestJWTUsingAuthCode:prtItem
                                                                               resource:resource
                                                                               clientId:clientId
                                                                                   code:code];
                            NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                                                 redirectUri, @"redirect_uri",
                                                                 clientId, @"client_id",
                                                                 @"2.0", @"windows_api_version",
                                                                 @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE,
                                                                 jwtToken, @"request",
                                                                 nil];
                            
                            //send JWT to token endpoint
                            [_ctx requestWithServer:_authority
                                       requestData:request_data
                              requestCorrelationId:[_ctx getCorrelationId]
                                   handledPkeyAuth:NO
                                 additionalHeaders:nil
                                 returnRawResponse:YES
                                        completion:^(NSDictionary *response) {
                                            
                                            if([response valueForKey:@"raw_response"])
                                            {
                                                ADBrokerJWEResponse* jweResp = [[ADBrokerJWEResponse alloc] initWithRawJWE:[response valueForKey:@"raw_response"]];
                                                response = [ADBrokerJwtHelper decryptJWEResponseUsingKeyDerivation:jweResp
                                                                                                           context:[jweResp headerContext]
                                                                                                               key:prtItem.sessionKey];
                                                
                                                //if id_token is not returned, Use id_token from PRT entry
                                                if([response valueForKey:OAUTH2_ID_TOKEN])
                                                {
                                                    [response setValue:[prtItem.userInformation rawIdToken]
                                                                forKey:OAUTH2_ID_TOKEN];
                                                }
                                            }
                                            
                                            ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
                                            item.resource = resource;
                                            item.clientId = clientId;
                                            ADAuthenticationResult* result = [_ctx processTokenResponse:response
                                                                                               forItem:item
                                                                                           fromRefresh:NO
                                                                                  requestCorrelationId:[_ctx getCorrelationId]];
                                            
                                            if(result.status == AD_SUCCEEDED)
                                            {
                                                //save AT and RT in the app key specific cache
                                                id<ADTokenCacheStoring> cacheStore = [[ADBrokerKeychainTokenCacheStore alloc] initWithAppKey:appKey];
                                                [_ctx updateCacheToResult:result
                                                           cacheInstance:cacheStore
                                                               cacheItem:nil
                                                        withRefreshToken:nil];
                                                result = [_ctx updateResult:result
                                                                    toUser:_userPrincipalIdentifier];
                                            }
                                            completionBlock(result);
                                        }];
                        }
                    }];
}


-(NSString*) createRefreshTokenCredentialJWT:(ADBrokerPRTCacheItem*) item
{
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"kid" : [[NSUUID UUID] UUIDString],
                             @"ctx" : [ADBrokerHelpers convertBase64UrlStringToBase64NSString:[ctx adBase64UrlEncode]]
                             };
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"refresh_token" : [item primaryRefreshToken],                             @"iat" : [NSNumber numberWithInteger:iat]
                              };
    
    NSString* returnValue = [ADBrokerJwtHelper createSignedJWTUsingKeyDerivation:header
                                                                         payload:payload
                                                                         context:ctx
                                                                    symmetricKey:item.sessionKey];
    return returnValue;
    
}


- (NSString*)createPRTRequestJWTUsingAuthCode:(ADBrokerPRTCacheItem*) item
                                     resource:(NSString*) resource
                                     clientId:(NSString*) clientId
                                         code:(NSString*) code
{
    NSString* grantType = @"authorization_code";
    
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"typ" : @"JWT",
                             @"ctx" : [ADBrokerHelpers convertBase64UrlStringToBase64NSString:[ctx adBase64UrlEncode]]
                             };
    
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"resource" : resource,
                              @"client_id" : clientId,
                              grantType : code,
                              @"iss" : BROKER_CLIENT_ID,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
                              @"grant_type" : grantType,
                              @"aud" : _authority
                              };
    
    NSString* returnValue = [ADBrokerJwtHelper createSignedJWTUsingKeyDerivation:header
                                                                         payload:payload
                                                                         context:ctx
                                                                    symmetricKey:item.sessionKey];
    return returnValue;
}

- (NSString*)createAccessTokenRequestJWTUsingPRT:(ADBrokerPRTCacheItem*) item
                                        resource:(NSString*) resource
                                        clientId:(NSString*) clientId
{
    NSString* grantType = @"refresh_token";
    
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"typ" : @"JWT",
                             @"ctx" : [ADBrokerHelpers convertBase64UrlStringToBase64NSString:[ctx adBase64UrlEncode]]
                             };
    
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"resource" : resource,
                              @"client_id" : clientId,
                              @"refresh_token" : [item primaryRefreshToken],
                              @"iss" : BROKER_CLIENT_ID,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
                              @"grant_type" : grantType,
                              @"aud" : _authority
                              };
    
    NSString* returnValue = [ADBrokerJwtHelper createSignedJWTUsingKeyDerivation:header
                                                                         payload:payload
                                                                         context:ctx
                                                                    symmetricKey:item.sessionKey];
    return returnValue;
}


- (NSString*)createPRTRequestJWTUsingBrokerRT:(NSString*)brokerRefreshToken
{
    RegistrationInformation* identity = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:nil];
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
    
    NSString* prtRequestJWT = [ADBrokerJwtHelper createSignedJWTforHeader:header
                                                                  payload:payload
                                                               signingKey:[identity privateKey]];
    identity = nil;
    return prtRequestJWT;
}


//Understands and processes the access token response:
- (ADAuthenticationResult *)processPRTResponse:(NSDictionary *)response
                                       forItem:(ADBrokerPRTCacheItem*)item
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
    
    NSString* refreshToken = [response objectForKey:OAUTH2_REFRESH_TOKEN];
    if (![NSString adIsStringNilOrBlank:refreshToken])
    {
        item.primaryRefreshToken    = refreshToken;
        item.authority = _authority;
        
        // Token response
        id      expires_in = [response objectForKey:OAUTH2_EXPIRES_IN];
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
        
        item.tokenType = [response objectForKey:OAUTH2_TOKEN_TYPE];
        item.expiresOn       = expires;
        NSString* idToken = [response objectForKey:OAUTH2_ID_TOKEN];
        if (idToken)
        {
            ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:idToken error:nil];
            if (userInfo)
            {
                item.userInformation = userInfo;
            }
        }
        item.accessToken = @"placeholder-value";
        //handle JWE
        NSString* rawJwe = [response objectForKey:OAUTH2_SESSION_JWE_KEY];
        RegistrationInformation* regInfo = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:nil];
        item.sessionKey = [ADBrokerJwtHelper getSessionKeyFromEncryptedJWT:rawJwe
                                                             privateKeyRef:[regInfo
                                                                            sessionTransportPrivateKey]
                                                                     error:&error];
        regInfo = nil;
        return [ADAuthenticationResult resultFromTokenCacheStoreItem:item
                                           multiResourceRefreshToken:NO];
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

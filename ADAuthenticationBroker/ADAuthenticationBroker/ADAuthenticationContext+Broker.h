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

#import <Foundation/Foundation.h>

@interface ADAuthenticationContext (Broker)

typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

//Requests an OAuth2 code to be used for obtaining a token:
-(void) requestCodeByResource: (NSString*) resource
                     clientId: (NSString*) clientId
                  redirectUri: (NSURL*) redirectUri
                        scope: (NSString*) scope /*for future use */
                       userId: (NSString*) userId
               promptBehavior: (ADPromptBehavior) promptBehavior
         extraQueryParameters: (NSString*) queryParams
       refreshTokenCredential: (NSString*) refreshTokenCredential
                correlationId: (NSUUID*) correlationId
                   completion: (ADAuthorizationCodeCallback) completionBlock;

- (void)request:(NSString *)authorizationServer
    requestData:(NSDictionary *)request_data
requestCorrelationId: (NSUUID*) requestCorrelationId
isHandlingPKeyAuthChallenge: (BOOL) isHandlingPKeyAuthChallenge
additionalHeaders:(NSDictionary *)additionalHeaders
returnRawResponse:(BOOL)returnRawResponse
     completion:( void (^)(NSDictionary *) )completionBlock;

- (ADAuthenticationResult *)processTokenResponse: (NSDictionary *)response
                                         forItem: (ADTokenCacheStoreItem*)item
                                     fromRefresh: (BOOL) fromRefreshTokenWorkflow
                            requestCorrelationId: (NSUUID*) requestCorrelationId;

-(void) internalAcquireTokenWithResource: (NSString*) resource
                                clientId: (NSString*) clientId
                             redirectUri: (NSURL*) redirectUri
                          promptBehavior: (ADPromptBehavior) promptBehavior
                                  silent: (BOOL) silent /* Do not show web UI for authorization. */
                                  userId: (NSString*) userId
                                   scope: (NSString*) scope
                    extraQueryParameters: (NSString*) queryParams
                                tryCache: (BOOL) tryCache /* set internally to avoid infinite recursion */
                       validateAuthority: (BOOL) validateAuthority
                           correlationId: (NSUUID*) correlationId
                         completionBlock: (ADAuthenticationCallback)completionBlock;

-(void) updateCacheToResult: (ADAuthenticationResult*) result
              cacheInstance: (id<ADTokenCacheStoring>) tokenCacheStoreInstance
                  cacheItem: (ADTokenCacheStoreItem*) cacheItem
           withRefreshToken: (NSString*) refreshToken;

-(ADAuthenticationResult*) updateResult: (ADAuthenticationResult*) result
                                 toUser: (NSString*) userId;

-(ADAuthenticationError*) errorFromDictionary: (NSDictionary*) dictionary
                                    errorCode: (ADErrorCode) errorCode;

-(void) acquireTokenWithResource: (NSString*) resource
                        clientId: (NSString*) clientId
                     redirectUri: (NSURL*) redirectUri
                          userId: (NSString*) userId
                           scope: (NSString*) scope
            extraQueryParameters: (NSString*) extraQueryParameters
                 completionBlock: (ADAuthenticationCallback) completionBlock;

@end

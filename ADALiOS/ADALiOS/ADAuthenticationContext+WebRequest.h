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

@interface ADAuthenticationContext (WebRequest)

- (void)executeRequest:(NSString *)authorizationServer
           requestData:(NSDictionary *)request_data
              resource:(NSString *) resource
              clientId:(NSString*) clientId
  requestCorrelationId:(NSUUID*) requestCorrelationId
       handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
     additionalHeaders:(NSDictionary *)additionalHeaders
            completion:(ADAuthenticationCallback)completionBlock;

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
               completion:( void (^)(NSDictionary *) )completionBlock;

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
               completion:( void (^)(NSDictionary *) )completionBlock;

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock;

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
       refreshTokenCredential:(NSString*)refreshTokenCredential
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock;

- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
       refreshTokenCredential:(NSString*)refreshTokenCredential
                       silent:(BOOL)silent
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock;

@end

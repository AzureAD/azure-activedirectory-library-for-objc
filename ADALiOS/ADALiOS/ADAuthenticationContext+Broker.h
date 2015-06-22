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
typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

@interface ADAuthenticationContext (Broker)

+ (BOOL)canUseBroker;
+ (void)internalHandleBrokerResponse:(NSURL*)response;

- (void)callBrokerForAuthority:(NSString*)authority
                      resource:(NSString*)resource
                      clientId:(NSString*)clientId
                   redirectUri:(NSURL*)redirectUri
                promptBehavior:(ADPromptBehavior)promptBehavior
                        userId:(ADUserIdentifier*)userId
          extraQueryParameters:(NSString*)queryParams
                 correlationId:(NSString*)correlationId
               completionBlock:(ADAuthenticationCallback)completionBlock;

- (void)handleBrokerFromWebiewResponse:(NSString*)urlString
                              resource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                                userId:(ADUserIdentifier*)userId
                  extraQueryParameters:(NSString*)queryParams
                         correlationId:(NSUUID*)correlationId
                       completionBlock:(ADAuthenticationCallback)completionBlock;

@end

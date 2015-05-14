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

#import "ADAuthenticationContext+BrokerSDK.h"

@implementation ADAuthenticationContext (BrokerSDK)

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                          userId:(NSString*)userId
                           scope:(NSString*)scope
            extraQueryParameters:(NSString*)extraQueryParameters
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    [self internalAcquireTokenWithResource:resource
                                  clientId:clientId
                               redirectUri:redirectUri
                            promptBehavior:AD_PROMPT_AUTO
                                    silent:NO
                                    userId:userId
                                     scope:scope
                      extraQueryParameters:extraQueryParameters
                         validateAuthority:self.validateAuthority
                             correlationId:[self getCorrelationId]
                           completionBlock:completionBlock];
}

@end

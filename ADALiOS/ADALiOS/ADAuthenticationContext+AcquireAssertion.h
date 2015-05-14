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

@interface ADAuthenticationContext (AcquireAssertion)

- (void)internalAcquireTokenForAssertion:(NSString*)samlAssertion
                                clientId:(NSString*)clientId
                             redirectUri:(NSString*)redirectUri
                                resource:(NSString*)resource
                           assertionType:(ADAssertionType)assertionType
                                  userId:(NSString*)userId
                                   scope:(NSString*)scope
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock;

// Generic OAuth2 Authorization Request, obtains a token from a SAML assertion.
- (void)requestTokenByAssertion:(NSString *)samlAssertion
                  assertionType:(ADAssertionType)assertionType
                       resource:(NSString *)resource
                       clientId:(NSString*)clientId
                          scope:(NSString*)scope //For future use
                  correlationId:(NSUUID*)correlationId
                     completion:(ADAuthenticationCallback)completionBlock;

@end

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

@interface ADAuthenticationContext (AcquireToken)


// Entry point to acquire a token going through the entire flow
- (void)internalAcquireTokenWithResource:(NSString*)resource
                                clientId:(NSString*)clientId
                             redirectUri:(NSURL*)redirectUri
                          promptBehavior:(ADPromptBehavior)promptBehavior
                                  silent:(BOOL)silent /* Do not show web UI for authorization. */
                                  userId:(NSString*)userId
                                   scope:(NSString*)scope
                    extraQueryParameters:(NSString*)queryParams
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock;

// For use after the authority has been validated
- (void)validatedAcquireTokenWithResource:(NSString*)resource
                                 clientId:(NSString*)clientId
                              redirectUri:(NSURL*)redirectUri
                           promptBehavior:(ADPromptBehavior)promptBehavior
                                   silent:(BOOL)silent /* Do not show web UI for authorization. */
                                   userId:(NSString*)userId
                                    scope:(NSString*)scope
                     extraQueryParameters:(NSString*)queryParams
                            correlationId:(NSUUID*)correlationId
                          completionBlock:(ADAuthenticationCallback)completionBlock;

// Bypasses the cache and attempts to request a token from the server, generally called after
// attempts to use cached tokens failed
- (void) requestTokenWithResource: (NSString*) resource
                         clientId: (NSString*) clientId
                      redirectUri: (NSURL*) redirectUri
                   promptBehavior: (ADPromptBehavior) promptBehavior
                           silent: (BOOL) silent /* Do not show web UI for authorization. */
                           userId: (NSString*) userId
                            scope: (NSString*) scope
             extraQueryParameters: (NSString*) queryParams
                    correlationId: (NSUUID*) correlationId
                  completionBlock: (ADAuthenticationCallback)completionBlock;

// This version allows "silent" requests where it will attempt to make the network call and fail if any user interaction
// is required
- (void) requestTokenWithResource: (NSString*) resource
                         clientId: (NSString*) clientId
                      redirectUri: (NSURL*) redirectUri
                   promptBehavior: (ADPromptBehavior) promptBehavior
                      allowSilent: (BOOL) allowSilent
                           userId: (NSString*) userId
                            scope: (NSString*) scope
             extraQueryParameters: (NSString*) queryParams
                    correlationId: (NSUUID*) correlationId
                  completionBlock: (ADAuthenticationCallback)completionBlock;

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
                  resource:(NSString *)resource
                  clientId:(NSString*)clientId
               redirectUri:(NSURL*)redirectUri
                     scope:(NSString*)scope
             correlationId:(NSUUID*)correlationId
                completion:(ADAuthenticationCallback)completionBlock;


- (void)internalAcquireTokenByRefreshToken:(NSString*)refreshToken
                                  clientId:(NSString*)clientId
                               redirectUri:(NSString*)redirectUri
                                  resource:(NSString*)resource
                                    userId:(NSString*)userId
                                 cacheItem:(ADTokenCacheStoreItem*)cacheItem
                         validateAuthority:(BOOL)validateAuthority
                             correlationId:(NSUUID*)correlationId
                           completionBlock:(ADAuthenticationCallback)completionBlock;

@end

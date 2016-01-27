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

#pragma once

@class ADAuthenticationError;
@class ADURLProtocol;

@protocol ADAuthMethodHandler

+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge*)challenge
             connection:(NSURLConnection*)connection
               protocol:(ADURLProtocol*)protocol;
+ (void)resetHandler;

@end

//Intercepts HTTPS protocol for the application in order to allow
//NTLM with client-authentication. The class is not thread-safe.
@interface ADURLProtocol : NSURLProtocol <NSURLConnectionDelegate, NSURLConnectionDataDelegate>

+ (void)registerHandler:(Class<ADAuthMethodHandler>)handler
             authMethod:(NSString*)authMethod;

+ (BOOL)registerProtocol;
+ (void)unregisterProtocol;

- (void)startLoading:(NSURL*)url;

@end

// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADAuthenticationRequest.h"

@interface ADAuthenticationRequest (AcquireToken)

#if TARGET_OS_WATCH
/*! This is an API exposed for WatchOS only. The authData is the ADTokenCacheItem transmitted from paired phone to watch. Internally, this method will save this authData info into the cache on Watch, and then call acquireToken to finish the authentication process as the standard ADAL library does
 @param authData: the ADTokenCacheItem saved on the paired phone cache and then transmitted from phone to watch
 @param completionBlock: the callback handler after the authentication finishes
 */
- (void)acquireTokenWithAuthData:(NSData *)authData
                 completionBlock: (ADAuthenticationCallback)completionBlock;
#endif


- (void)acquireToken:(ADAuthenticationCallback)completionBlock;

// For use after the authority has been validated
- (void)validatedAcquireToken:(ADAuthenticationCallback)completionBlock;

// Bypasses the cache and attempts to request a token from the server, generally called after
// attempts to use cached tokens failed
- (void)requestToken:(ADAuthenticationCallback)completionBlock;

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString*)code
           completionBlock:(ADAuthenticationCallback)completionBlock;

@end

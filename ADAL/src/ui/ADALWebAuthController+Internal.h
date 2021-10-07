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

#import "ADALAuthenticationContext.h"
#import "MSIDWebviewAuthorization.h"
#import "ADALWebAuthController.h"

@class ADALAuthenticationError;
@class WKWebView;

@interface ADALWebAuthController (Internal)

// Start the authentication process. Note that there are two different behaviours here dependent on whether the caller has provided
// a WebView to host the browser interface. If no WebView is provided, then a full window is launched that hosts a WebView to run
// the authentication process.
+ (void)startWithRequest:(ADALRequestParameters *)requestParams
          promptBehavior:(ADPromptBehavior)promptBehavior
            refreshToken:(NSString*)refreshToken
                 context:(ADALAuthenticationContext *)context
              completion:(MSIDWebviewAuthCompletionHandler)completionHandler;

#if TARGET_OS_IPHONE
+ (void)setInterruptedBrokerResult:(ADALAuthenticationResult*)result;
#endif // TARGET_OS_IPHONE




@end

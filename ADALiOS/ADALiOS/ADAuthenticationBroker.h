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

#include "ADAuthenticationContext.h"
#if TARGET_OS_IPHONE
//iOS:
#   include <UIKit/UIKit.h>
typedef UIWebView WebViewType;
#else
//OS X:
#   include <WebKit/WebKit.h>
typedef WebView   WebViewType;
#endif

@class ADAuthenticationError;
@class ADAuthenticationWindowController;
@class ADAuthenticationViewController;
@class ADAuthenticationWebViewController;

typedef void (^ADBrokerCallback) (ADAuthenticationError* error, NSURL*);

@interface ADAuthenticationBroker : NSObject
{
// OSX Universal Compatibility
@private
#if TARGET_OS_IPHONE
    ADAuthenticationViewController  *_authenticationPageController;
#else
    ADAuthenticationWindowController  *_authenticationPageController;
    NSModalSession                     _authenticationSession;
#endif
    ADAuthenticationWebViewController *_authenticationWebViewController;
    
    void (^_completionBlock)( ADAuthenticationError *, NSURL *);
}

+ (ADAuthenticationBroker *)sharedInstance;

// Start the authentication process. Note that there are two different behaviours here dependent on whether the caller has provided
// a WebView to host the browser interface. If no WebView is provided, then a full window is launched that hosts a WebView to run
// the authentication process. 
- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
parentController:(ViewController*) parent
      webView:(WebViewType*)webView
   fullScreen:(BOOL)fullScreen
correlationId:(NSUUID*)correlationId
   completion: (ADBrokerCallback) completionBlock;

- (void)cancel;

@end

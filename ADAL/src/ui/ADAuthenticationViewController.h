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

@protocol ADWebAuthDelegate;

@interface ADAuthenticationViewController :
#if TARGET_OS_IPHONE
UIViewController
#else
NSWindowController
{
    // In the legacy ObjC runtime (which is what we're stuck at for 32-bit Mac builds)
    // you can't define the ivars of a class in the implementation file.
    id<ADWebAuthDelegate> _delegate;
    WebViewType* _webView;
    /*__weak*/ NSProgressIndicator* _progressIndicator;
}
#endif

@property (weak, nonatomic) id<ADWebAuthDelegate>     delegate;
#if TARGET_OS_IPHONE
@property (weak, nonatomic) UIWebView * webView;
@property (weak, nonatomic) UIViewController * parentController;
@property BOOL fullScreen;
#else
@property (weak, nonatomic) WebView * webView;
#endif

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error;

- (void)startRequest:(NSURLRequest *)request;
- (void)loadRequest:(NSURLRequest *)request;
- (void)stop:(void (^)(void))completion;

- (void)startSpinner;
- (void)stopSpinner;

@end

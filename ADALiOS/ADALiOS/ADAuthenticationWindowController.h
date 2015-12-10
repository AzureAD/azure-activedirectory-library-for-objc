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

@class ADAuthenticationWebViewController;

@protocol ADAuthenticationDelegate;

@interface ADAuthenticationWindowController : NSWindowController <NSWindowDelegate, WebResourceLoadDelegate>
{
    IBOutlet WebView *_webView;
    __weak NSProgressIndicator *_progressIndicator;
    
    ADAuthenticationWebViewController*  _webViewController;
    id                                  _webViewResourceLoadDelegate;
    id<ADAuthenticationDelegate>        _delegate;
    
    BOOL      _complete;
    BOOL      _closed;
    
    NSURL    *_startURL;
    NSURL    *_endURL;
    
    // Counter for load/finish of webview requests
    __volatile int32_t _loadCounter;
}

@property (assign) IBOutlet NSProgressIndicator *progressIndicator;

@property (weak_delegate, nonatomic) id<ADAuthenticationDelegate> delegate;

- (id)initAtURL:(NSURL *)startURL endAtURL:(NSURL *)endURL;
- (void)start;
@end

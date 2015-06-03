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

#import "ADWebViewController.h"

@implementation ADWebViewController
{
    id<ADWebViewDelegate> _delegate;
    __weak UIWebView* _webView;
}

@synthesize delegate = _delegate;

- (id)initWithWebView:(UIWebView *)webView
{
    if (!webView)
        return nil;
    
    if (!(self = [super init]))
        return nil;
    
    _webView = webView;
    
    return self;
}

- (BOOL)webView:(UIWebView*)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
#pragma unused(webView)
#pragma unused(navigationType)
 
    return [_delegate shouldStartLoadWithRequest:request];
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
#pragma unused(webView)
    
    [_delegate didStartLoad];
}


- (void)webViewDidFinishLoad:(UIWebView *)webView
{
#pragma unused(webView)
    
    [_delegate didFinishLoad];
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
#pragma unused(webView)
    [_delegate didFailLoadWithError:error];
}

- (void)loadRequest:(NSURLRequest *)request
{
    [_webView loadRequest:request];
}

@end

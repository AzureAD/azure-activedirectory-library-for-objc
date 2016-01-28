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

#import "ADWebAuthDelegate.h"
#import "ADAuthenticationViewController.h"
#import "ADLogger.h"
#import "ADALFrameworkUtils.h"


@interface ADAuthenticationViewController ( ) <WebResourceLoadDelegate, WebPolicyDelegate, WebFrameLoadDelegate>
{
    NSProgressIndicator* _progressIndicator;
}

@end

@implementation ADAuthenticationViewController

- (void)loadView
{
    [self loadView:nil];
}

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error
{
    if (_webView)
    {
        [_webView setFrameLoadDelegate:self];
        [_webView setResourceLoadDelegate:self];
        [_webView setPolicyDelegate:self];
        
        return YES;
    }
    
    
    return NO;
}

#pragma mark - UIViewController Methods

- (void)viewDidLoad
{
    [super viewDidLoad];
}

#pragma mark - Event Handlers

// Authentication was cancelled by the user
- (IBAction)onCancel:(id)sender
{
#pragma unused(sender)
    [_delegate webAuthDidCancel];
}

// Fired 2 seconds after a page loads starts to show waiting indicator

- (void)stop:(void (^)(void))completion
{
}

- (void)startRequest:(NSURLRequest *)request
{
    [self loadRequest:request];

}

- (void)loadRequest:(NSURLRequest*)request
{
}

- (void)startSpinner
{
    [_progressIndicator setHidden:NO];
    [_progressIndicator startAnimation:nil];
}

#pragma mark - UIWebViewDelegate Protocol

- (void)webView:(WebView *)webView decidePolicyForNavigationAction:(NSDictionary *)actionInformation
        request:(NSURLRequest *)request
          frame:(WebFrame *)frame
decisionListener:(id<WebPolicyDecisionListener>)listener
{
    (void)webView;
    (void)actionInformation;
    (void)frame;
    
    if ([_delegate webAuthShouldStartLoadRequest:request])
    {
        [listener use];
    }
    else
    {
        [listener ignore];
    }
}

- (void)stopSpinner
{
    [_progressIndicator setHidden:YES];
    [_progressIndicator stopAnimation:nil];
}


- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    (void)sender;
    (void)frame;
    [_delegate webAuthDidFailWithError:error];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    (void)sender;
    (void)frame;
    [_delegate webAuthDidFailWithError:error];
}

@end

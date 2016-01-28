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
#import "UIApplication+ADExtensions.h"

NSString *const AD_FAILED_NO_CONTROLLER = @"The Application does not have a current ViewController";

@interface ADAuthenticationViewController ( ) <UIWebViewDelegate>
{
    UIActivityIndicatorView* _activityIndicator;
    UINavigationController* _navController;
}

@end

@implementation ADAuthenticationViewController

- (void)loadView
{
    [self loadView:nil];
}

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error
{
    // If we already have a webview then we assume it's already being displayed and just need to
    // hijack the delegate on the webview.
    if (_webView)
    {
        _webView.delegate = self;
        return YES;
    }
    
    if (!_parentController)
    {
        _parentController = [UIApplication adCurrentViewController];
    }
    
    if (!_parentController)
    {
        // Must have a parent view controller to start the authentication view
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_NO_MAIN_VIEW_CONTROLLER
                                                        protocolCode:nil
                                                        errorDetails:AD_FAILED_NO_CONTROLLER];
        
        if (error)
        {
            *error = adError;
        }
        return NO;
    }
    
    UIView* rootView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    [rootView setAutoresizesSubviews:YES];
    [rootView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    UIWebView* webView = [[UIWebView alloc] initWithFrame:rootView.frame];
    [webView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [webView setDelegate:self];
    [rootView addSubview:webView];
    _webView = webView;
    
    _activityIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [_activityIndicator setColor:[UIColor blackColor]];
    [_activityIndicator setCenter:rootView.center];
    [rootView addSubview:_activityIndicator];
    
    self.view = rootView;
    
    _navController = [[UINavigationController alloc] init];
    _navController.navigationBar.hidden = NO;
    
    UIBarButtonItem* cancelButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                                                  target:self
                                                                                  action:@selector(onCancel:)];
    self.navigationItem.leftBarButtonItem = cancelButton;
    [_navController pushViewController:self animated:NO];
    
    return NO;
}

#pragma mark - UIViewController Methods

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    if ( (NSUInteger)[[[UIDevice currentDevice] systemVersion] doubleValue] < 7)
    {
        [self.navigationController.navigationBar setTintColor:[UIColor darkGrayColor]];
    }
}

- (void)viewDidUnload
{
    DebugLog();
    
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    if ( UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad )
        // The device is an iPad running iPhone 3.2 or later.
        return YES;
    else
        return (interfaceOrientation == UIInterfaceOrientationPortrait);
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
    [_parentController dismissViewControllerAnimated:YES completion:completion];
    
    _parentController = nil;
    _delegate = nil;
}

- (void)startRequest:(NSURLRequest *)request
{
    [self loadRequest:request];
    
    if (_fullScreen)
    {
        [_navController setModalPresentationStyle:UIModalPresentationFullScreen];
    }
    else
    {
        [_navController setModalPresentationStyle:UIModalPresentationFormSheet];
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [_parentController presentViewController:_navController animated:YES completion:nil];
    });
}

- (void)loadRequest:(NSURLRequest*)request
{
    [_webView loadRequest:request];
}

- (void)startSpinner
{
    [_activityIndicator setHidden:NO];
    [_activityIndicator startAnimating];
}

#pragma mark - UIWebViewDelegate Protocol

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
#pragma unused(webView)
#pragma unused(navigationType)
    
    // Forward to the UIWebView controller
    return [_delegate webAuthShouldStartLoadRequest:request];
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
#pragma unused(webView)
    
    [_delegate webAuthDidStartLoad];
}

- (void)stopSpinner
{
    [_activityIndicator setHidden:YES];
    [_activityIndicator stopAnimating];
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
#pragma unused(webView)
    [_delegate webAuthDidFinishLoad];
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
#pragma unused(webView)
    [_delegate webAuthDidFailWithError:error];
}

@end

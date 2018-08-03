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

#import "ADWebAuthDelegate.h"
#import "ADAuthenticationViewController.h"
#import "ADLogger.h"
#import "ADALFrameworkUtils.h"
#import "UIApplication+ADExtensions.h"
#import <UIKit/UIKit.h>
#import "ADAppExtensionUtil.h"

NSString *const AD_FAILED_NO_CONTROLLER = @"The Application does not have a current ViewController";

@interface ADAuthenticationViewController ( ) <UIWebViewDelegate>
{
    UIActivityIndicatorView* _activityIndicator;
    UIBackgroundTaskIdentifier _bgTask;
    id _bgObserver;
    id _foregroundObserver;
}

@end

@implementation ADAuthenticationViewController


- (void)loadView
{
    [self loadView:nil];
}

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error
{
    /* Start background transition tracking,
     so we can start a background task, when app transitions to background */
    if (![ADAppExtensionUtil isExecutingInAppExtension])
    {
        [self startTrackingBackroundAppTransition];
    }

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
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER
                                               protocolCode:nil
                                               errorDetails:AD_FAILED_NO_CONTROLLER
                                              correlationId:nil];

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
    webView.accessibilityIdentifier = @"ADAL_SIGN_IN_WEBVIEW";
    _activityIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [_activityIndicator setColor:[UIColor blackColor]];
    [_activityIndicator setCenter:rootView.center];
    [rootView addSubview:_activityIndicator];

    self.view = rootView;

    UIBarButtonItem* cancelButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                                                  target:self
                                                                                  action:@selector(onCancel:)];
    self.navigationItem.leftBarButtonItem = cancelButton;

    return YES;
}

/*! set webview's delegate to nil when the view controller
 is deallocated, or it might crash ADAL. */
-(void)dealloc
{
    [self cleanupBackgroundTask];
    [_webView setDelegate:nil];
    _webView = nil;
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
    (void)sender;
    [_delegate webAuthDidCancel];
}

// Fired 2 seconds after a page loads starts to show waiting indicator

- (void)stop:(void (^)(void))completion
{
    [self cleanupBackgroundTask];

    //if webview is created by us, dismiss and then complete and return;
    //otherwise just complete and return.
    if (_parentController)
    {
        [_parentController dismissViewControllerAnimated:YES completion:completion];
    }
    else
    {
        completion();
    }

    _parentController = nil;
    _delegate = nil;
}

- (void)startRequest:(NSURLRequest *)request
{
    [self loadRequest:request];

    UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:self];

    if (_fullScreen)
    {
        [navController setModalPresentationStyle:UIModalPresentationFullScreen];
    }
    else
    {
        [navController setModalPresentationStyle:UIModalPresentationFormSheet];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [_parentController presentViewController:navController animated:YES completion:nil];
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
    (void)webView;
    (void)navigationType;

    // Forward to the UIWebView controller
    return [_delegate webAuthShouldStartLoadRequest:request];
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
    [_delegate webAuthDidStartLoad:webView.request.URL];
}

- (void)stopSpinner
{
    [_activityIndicator setHidden:YES];
    [_activityIndicator stopAnimating];
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    [_delegate webAuthDidFinishLoad:webView.request.URL];
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
    (void)webView;
    [_delegate webAuthDidFailWithError:error];
}

#pragma mark - Background task

- (void)startTrackingBackroundAppTransition
{
    if (_bgObserver)
    {
        return;
    }

    _bgObserver = [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillResignActiveNotification
                                                                    object:nil
                                                                     queue:nil
                                                                usingBlock:^(__unused NSNotification *notification)
                   {
                       MSID_LOG_VERBOSE(nil, @"Application will resign active");
                       [self startTrackingForegroundAppTransition];
                       [self startBackgroundTask];
                   }];
}

- (void)stopTrackingBackgroundAppTransition
{
    if (_bgObserver)
    {
        MSID_LOG_VERBOSE(nil, @"Stop background application tracking");
        [[NSNotificationCenter defaultCenter] removeObserver:_bgObserver];
        _bgObserver = nil;
    }
}

- (void)startTrackingForegroundAppTransition
{
    if (_foregroundObserver)
    {
        return;
    }

    _foregroundObserver = [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                                            object:nil
                                                                             queue:nil
                                                                        usingBlock:^(__unused NSNotification * _Nonnull note) {

                                                                            MSID_LOG_VERBOSE(nil, @"Application did become active");
                                                                            [self stopBackgroundTask];
                                                                            [self stopTrackingForegroundAppTransition];
                                                                        }];
}

- (void)stopTrackingForegroundAppTransition
{
    if (_foregroundObserver)
    {
        MSID_LOG_VERBOSE(nil, @"Stop foreground application tracking");

        [[NSNotificationCenter defaultCenter] removeObserver:_foregroundObserver];
        _foregroundObserver = nil;
    }
}

/*
 Background task execution:
 https://forums.developer.apple.com/message/253232#253232
 */

- (void)startBackgroundTask
{
    if (_bgTask != UIBackgroundTaskInvalid)
    {
        // Background task already started
        return;
    }

    MSID_LOG_INFO(nil, @"Start background app task");

    _bgTask = [[ADAppExtensionUtil sharedApplication] beginBackgroundTaskWithName:@"Interactive login"
                                                                expirationHandler:^{
                                                                    MSID_LOG_INFO(nil, @"Background task expired");
                                                                    [self stopBackgroundTask];
                                                                    [self stopTrackingForegroundAppTransition];
                                                                }];
}

- (void)stopBackgroundTask
{
    if (_bgTask == UIBackgroundTaskInvalid)
    {
        // Background task already ended or not started
        return;
    }

    MSID_LOG_INFO(nil, @"Stop background task");
    [[ADAppExtensionUtil sharedApplication] endBackgroundTask:_bgTask];
    _bgTask = UIBackgroundTaskInvalid;
}

- (void)cleanupBackgroundTask
{
    [self stopTrackingBackgroundAppTransition];

    // If authentication is stopped while app is in background
    [self stopTrackingForegroundAppTransition];
    [self stopBackgroundTask];
}

@end

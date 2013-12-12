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

#import "UIApplicationExtensions.h"
#import "ADAuthenticationContext.h"
#import "WebAuthenticationDelegate.h"
#import "WebAuthenticationWebViewController.h"
#import "WebAuthenticationViewController.h"
#import "WebAuthenticationBroker.h"


static NSString *const WAB_FAILED_ERROR         = @"Authorization Failed";
static NSString *const WAB_FAILED_ERROR_CODE    = @"Authorization Failed: %ld";

static NSString *const WAB_FAILED_CANCELLED     = @"The user cancelled the authorization request";
static NSString *const WAB_FAILED_NO_CONTROLLER = @"The Application does not have a current ViewController";
static NSString *const WAB_FAILED_NO_RESOURCES  = @"The required resource bundle could not be loaded";

// Private interface declaration
@interface WebAuthenticationBroker () <WebAuthenticationDelegate>
@end

// Implementation
@implementation WebAuthenticationBroker
{
    WebAuthenticationViewController    *_authenticationViewController;
    WebAuthenticationWebViewController *_authenticationWebViewController;
    
    NSLock                             *_completionLock;
    
    void (^_completionBlock)( ADAuthenticationError *, NSURL *);
}

#pragma mark Shared Instance Methods

+ (WebAuthenticationBroker *)sharedInstance
{
    static WebAuthenticationBroker *broker     = nil;
    static dispatch_once_t          predicate;
    
    dispatch_once( &predicate, ^{
        broker = [[self allocPrivate] init];
    });
    
    return broker;
}

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    // [super alloc] calls to NSObject, and that calls [class allocWithZone:]
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

#pragma mark - Initialization

- (id)init
{
    self = [super init];
    
    if ( self )
    {
        _completionLock = [[NSLock alloc] init];
    }
    
    return self;
}

#pragma mark - Private Methods

static NSString *_resourcePath = nil;

+ (NSString *)resourcePath
{
    return _resourcePath;
}

+ (void)setResourcePath:(NSString *)resourcePath
{
    _resourcePath = resourcePath;
}

// Retrive the bundle containing the resources for the library
+ (NSBundle *)frameworkBundle
{
    static NSBundle       *bundle     = nil;
    static dispatch_once_t predicate;
    
    @synchronized(self)
    {
        dispatch_once( &predicate,
                      ^{
                          NSString* mainBundlePath      = [[NSBundle mainBundle] resourcePath];
                          NSString* frameworkBundlePath = nil;
                          
                          if ( _resourcePath != nil )
                          {
                              frameworkBundlePath = [[mainBundlePath stringByAppendingPathComponent:_resourcePath] stringByAppendingPathComponent:@"ADALiOSBundle.bundle"];
                          }
                          else
                          {
                              frameworkBundlePath = [mainBundlePath stringByAppendingPathComponent:@"ADALiOSBundle.bundle"];
                          }
                          
                          bundle = [NSBundle bundleWithPath:frameworkBundlePath];
                          if (!bundle)
                          {
                              AD_LOG_WARN(@"Cannot load ADALiOS bundle", frameworkBundlePath);
                          }
                      });
    }
    
    return bundle;
}

// Retrieve the current storyboard from the resources for the library
+ (UIStoryboard *)storyboard
{
    if ( UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad )
    {
        // The device is an iPad running iPhone 3.2 or later.
        return [UIStoryboard storyboardWithName:@"IPAL_iPad_Storyboard" bundle:[self frameworkBundle]];
    }
    else
    {
        // The device is an iPhone or iPod touch.
        return [UIStoryboard storyboardWithName:@"IPAL_iPhone_Storyboard" bundle:[self frameworkBundle]];
    }
}

#pragma mark - Public Methods

// Start the authentication process. Note that there are two different behaviours here dependent on whether the caller has provided
// a WebView to host the browser interface. If no WebView is provided, then a full window is launched that hosts a WebView to run
// the authentication process. If a WebView is provided, then that is used instead of launching a complete window.
- (void)start:(NSURL *)startURL end:(NSURL *)endURL ssoMode:(BOOL)ssoMode webView:(UIWebView *)webView fullScreen:(BOOL)fullScreen completion:(ADBrokerCallback)completionBlock
{
    NSAssert( startURL != nil, @"startURL is nil" );
    NSAssert( endURL != nil, @"endURL is nil" );
    NSAssert( completionBlock != nil, @"completionBlock is nil" );
    
    // Save the completion block
    _completionBlock = [completionBlock copy];
    
    if ( nil == webView )
    {
        // Must have a parent view controller to start the authentication view
        UIViewController *parent = [UIApplication currentViewController];
        
        if ( parent )
        {
            // Load our resource bundle, find the navigation controller for the authentication view, and then the authentication view
            UINavigationController *navigationController = [[self.class storyboard] instantiateViewControllerWithIdentifier:@"LogonNavigator"];
            
            _authenticationViewController = (WebAuthenticationViewController *)[navigationController.viewControllers objectAtIndex:0];
            
            if ( _authenticationViewController )
            {
                _authenticationViewController.delegate = self;
                
                if ( fullScreen == YES )
                    [navigationController setModalPresentationStyle:UIModalPresentationFullScreen];
                else
                    [navigationController setModalPresentationStyle:UIModalPresentationFormSheet];
                
                // Show the authentication view
                [parent presentViewController:navigationController animated:YES completion:^{
                    // Instead of loading the URL immediately on completion, get the UI on the screen
                    // and then dispatch the call to load the authorization URL
                    dispatch_async( dispatch_get_main_queue(), ^{
                        [_authenticationViewController startWithURL:startURL endAtURL:endURL ssoMode:ssoMode];
                    });
                }];
            }
            else
            {
                // Dispatch the completion block
                ADAuthenticationError   *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_APPLICATION protocolCode:nil errorDetails:WAB_FAILED_NO_RESOURCES];
                dispatch_async( dispatch_get_main_queue(), ^{
                    _completionBlock( error, nil );
                });
            }
        }
        else
        {
            // Dispatch the completion block
            ADAuthenticationError   *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_APPLICATION protocolCode:nil errorDetails:WAB_FAILED_NO_CONTROLLER];
            dispatch_async( dispatch_get_main_queue(), ^{
                _completionBlock( error, nil );
            });
        }
    }
    else
    {
        // Use the application provided WebView
        _authenticationWebViewController = [[WebAuthenticationWebViewController alloc] initWithWebView:webView startAtURL:startURL endAtURL:endURL ssoMode:ssoMode];
        
        if ( _authenticationWebViewController )
        {
            // Show the authentication view
            _authenticationWebViewController.delegate = self;
            [_authenticationWebViewController start];
        }
        else
        {
            // Dispatch the completion block
            ADAuthenticationError   *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_APPLICATION protocolCode:nil errorDetails:WAB_FAILED_NO_RESOURCES];
            dispatch_async( dispatch_get_main_queue(), ^{
                _completionBlock( error, nil );
            });
        }
    }
}

- (void)cancel
{
    [self webAuthenticationDidCancel];
}

#pragma mark - Private Methods

- (void)dispatchCompletionBlock:(ADAuthenticationError *)error URL:(NSURL *)url
{
    // NOTE: It is possible that race between a successful completion
    //       and the user cancelling the authentication dialog can
    //       occur causing this method to be called twice. The race
    //       cannot be blocked at its root, and so this method must
    //       be resilient to this condition and should not generate
    //       two callbacks.
    [_completionLock lock];
    
    if ( _completionBlock )
    {
        void (^completionBlock)( ADAuthenticationError *, NSURL *) = _completionBlock;
        _completionBlock = nil;
        
        dispatch_async( dispatch_get_main_queue(), ^{
            completionBlock( error, url );
        });
    }
    
    [_completionLock unlock];
}

#pragma mark - WebAuthenticationDelegate

// The user cancelled authentication
- (void)webAuthenticationDidCancel
{
    DebugLog();
    
    // Dispatch the completion block

    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_CANCEL protocolCode:nil errorDetails:WAB_FAILED_CANCELLED];
    
    if ( nil != _authenticationViewController)
    {
        // Dismiss the authentication view and dispatch the completion block
        [[UIApplication currentViewController] dismissViewControllerAnimated:YES completion:^{
            [self dispatchCompletionBlock:error URL:nil];
        }];
    }
    else
    {
        [_authenticationWebViewController stop];
        [self dispatchCompletionBlock:error URL:nil];
    }
    
    _authenticationViewController    = nil;
    _authenticationWebViewController = nil;
}

// Authentication completed at the end URL
- (void)webAuthenticationDidCompleteWithURL:(NSURL *)endURL
{
    DebugLog();
    
    if ( nil != _authenticationViewController)
    {
        // Dismiss the authentication view and dispatch the completion block
        [[UIApplication currentViewController] dismissViewControllerAnimated:YES completion:^{
            [self dispatchCompletionBlock:nil URL:endURL];
        }];
    }
    else
    {
        [_authenticationWebViewController stop];
        [self dispatchCompletionBlock:nil URL:endURL];
    }
    
    _authenticationViewController    = nil;
    _authenticationWebViewController = nil;
}

// Authentication failed somewhere
- (void)webAuthenticationDidFailWithError:(NSError *)error
{
    // Dispatch the completion block
    ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription];
    
    if ( nil != _authenticationViewController)
    {
        // Dismiss the authentication view and dispatch the completion block
        [[UIApplication currentViewController] dismissViewControllerAnimated:YES completion:^{
            [self dispatchCompletionBlock:adError URL:nil];
        }];
    }
    else
    {
        [_authenticationWebViewController stop];
        [self dispatchCompletionBlock:adError URL:nil];
    }
    
    _authenticationViewController    = nil;
    _authenticationWebViewController = nil;
}

@end

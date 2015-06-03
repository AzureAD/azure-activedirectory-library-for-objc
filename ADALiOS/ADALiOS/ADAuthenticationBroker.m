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

#import "ADALiOS.h"
#import "ADOAuth2Constants.h"
#import "UIApplication+ADExtensions.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationDelegate.h"
#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationSettings.h"
#import "ADCustomHeaderHandler.h"
#import "ADAuthenticationWindowController.h"
#import "ADNTLMHandler.h"

NSString * const ADAuthenticationWillStartNotification = @"ADAuthenticationWillStartNotification";

// Private interface declaration
@interface ADAuthenticationBroker () <ADAuthenticationDelegate>

@property (retain) ADAuthenticationWebViewController* authenticationWebViewController;
@property (retain) ADAuthenticationWindowController* windowController;
@property (retain) NSString* refreshTokenCredential;

@end

// Implementation
@implementation ADAuthenticationBroker
{
    ADAuthenticationWindowController *  _windowController;
    ADAuthenticationWebViewController * _authenticationWebViewController;
    
    BOOL                                _ntlmSession;
    NSString*                           _refreshTokenCredential;
    
    
    NSLock *                            _completionLock;
    
    void (^_completionBlock)( ADAuthenticationError *, NSURL *);
}

@synthesize authenticationWebViewController = _authenticationWebViewController;
@synthesize windowController = _windowController;
@synthesize refreshTokenCredential = _refreshTokenCredential;

#pragma mark Shared Instance Methods

+ (ADAuthenticationBroker *)sharedInstance
{
    static ADAuthenticationBroker *broker     = nil;
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
    if (!(self = [super init]))
        return nil;
    
    _completionLock = [[NSLock alloc] init];
    _ntlmSession = NO;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(authWindowWillShow:)
                                                 name:ADAuthenticationWillStartNotification
                                               object:nil];
    
    return self;
}

#pragma mark - Private Methods

-(NSURL*) addToURL: (NSURL*) url
     correlationId: (NSUUID*) correlationId
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@",
                                 [url absoluteString], OAUTH2_CORRELATION_ID_REQUEST_VALUE, [correlationId UUIDString]]];
}

#pragma mark - Public Methods

static NSString *_resourcePath = nil;

+ (NSString *)resourcePath
{
    return _resourcePath;
}

+ (void)setResourcePath:(NSString *)resourcePath
{
    _resourcePath = resourcePath;
}

// Retrive the bundle containing the resources for the library. May return nil, if the bundle
// cannot be loaded.
+ (NSBundle *)frameworkBundle
{
    static NSBundle       *bundle     = nil;
    static dispatch_once_t predicate;
    
    @synchronized(self)
    {
        dispatch_once( &predicate,
                      ^{
                          
                          NSString* mainBundlePath      = [[NSBundle mainBundle] resourcePath];
                          AD_LOG_VERBOSE_F(@"Resources Loading", @"Attempting to load resources from: %@", mainBundlePath);
                          NSString* frameworkBundlePath = nil;
                          
                          if ( _resourcePath != nil )
                          {
                              frameworkBundlePath = [[mainBundlePath stringByAppendingPathComponent:_resourcePath] stringByAppendingPathComponent:@"ADALiOS.bundle"];
                          }
                          else
                          {
                              frameworkBundlePath = [mainBundlePath stringByAppendingPathComponent:@"ADALiOS.bundle"];
                          }
                          
                          bundle = [NSBundle bundleWithPath:frameworkBundlePath];
                          if (!bundle)
                          {
                              AD_LOG_INFO_F(@"Resource Loading", @"Failed to load framework bundle. Application main bundle will be attempted.");
                          }
                      });
    }
    
    return bundle;
}

- (void)authWindowWillShow:(NSNotification*)notification
{
#pragma unused (notification)
    _ntlmSession = [ADNTLMHandler startWebViewNTLMHandlerWithError:nil];
    if (_ntlmSession)
    {
        AD_LOG_INFO(@"Authorization UI", @"NTLM support enabled.");
    }
    
    if(![NSString adIsStringNilOrBlank:_refreshTokenCredential])
    {
        [ADCustomHeaderHandler addCustomHeaderValue:_refreshTokenCredential
                                       forHeaderKey:@"x-ms-RefreshTokenCredential"
                                       forSingleUse:YES];
        [self setRefreshTokenCredential:nil];
    }
}


- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
refreshTokenCredential:(NSString*)refreshTokenCredential
#if TARGET_OS_IPHONE
parentController:(UIViewController *)parent
#endif // TARGET_OS_IPHONE
      webView:(ADWebView *)webView
   fullScreen:(BOOL)fullScreen
correlationId:(NSUUID *)correlationId
   completion:(ADBrokerCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(startURL);
    THROW_ON_NIL_ARGUMENT(endURL);
    THROW_ON_NIL_ARGUMENT(correlationId);
    THROW_ON_NIL_ARGUMENT(completionBlock)
    //AD_LOG_VERBOSE(@"Authorization", startURL.absoluteString);
    
    startURL = [self addToURL:startURL correlationId:correlationId];//Append the correlation id
    
    // Save the completion block
    _completionBlock = [completionBlock copy];
    ADAuthenticationError* error = nil;

    if (webView)
    {
        AD_LOG_INFO(@"Authorization UI", @"Use the application provided WebView.");
        // Use the application provided WebView
        [self setAuthenticationWebViewController:[[ADAuthenticationWebViewController alloc] initWithWebView:webView startURL:startURL endURL:endURL]];
        
        if ( _authenticationWebViewController )
        {
            // Show the authentication view
            _authenticationWebViewController.delegate = self;
            [_authenticationWebViewController start];
        }
        else
        {
            // Dispatch the completion block
            error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MISSING_RESOURCES
                                                           protocolCode:nil
                                                           errorDetails:AD_FAILED_NO_RESOURCES];
        }
    }
    else
    {
        _windowController = [[ADAuthenticationWindowController alloc] init];
        if (_windowController)
        {
#if TARGET_OS_IPHONE
            [_windowController setParentController:parent];
            [_windowController setFullScreen:fullScreen];
#endif // TARGET_OS_IPHONE
            [_windowController setDelegate:self];
            
            [self setRefreshTokenCredential:refreshTokenCredential];
            error = [_windowController showWindowWithStartURL:startURL
                                                       endURL:endURL];
        }
    }
    
    //Error occurred above. Dispatch the callback to the caller:
    if (error)
    {
        dispatch_async( [ADAuthenticationSettings sharedInstance].dispatchQueue, ^{
            _completionBlock( error, nil );
        });
    }
}

- (void)cancel
{
    [self webAuthenticationDidCancel];
}

- (BOOL)cancelWithError:(int)errorcode
                details:(NSString*)details
{
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:errorcode
                                                                          protocolCode:nil
                                                                          errorDetails:details];
    return [self endWebAuthenticationWithError:error orURL:nil];
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
    if (_ntlmSession)
    {
        [ADNTLMHandler endWebViewNTLMHandler];
    }
    
    if ( _completionBlock )
    {
        void (^completionBlock)( ADAuthenticationError *, NSURL *) = _completionBlock;
        _completionBlock = nil;
        
        dispatch_async( [ADAuthenticationSettings sharedInstance].dispatchQueue, ^{
            completionBlock( error, url );
        });
    }
    
    [_completionLock unlock];
}

#pragma mark - ADAuthenticationDelegate

- (BOOL)endWebAuthenticationWithError:(ADAuthenticationError*) error
                                orURL:(NSURL*)endURL
{
    if ( nil != _windowController)
    {
        // Dismiss the authentication view and dispatch the completion block
        [_windowController dismissAnimated:YES completion:^{
            [self dispatchCompletionBlock:error URL:endURL];
        }];
    }
    else if (nil != _authenticationWebViewController)
    {
        [_authenticationWebViewController stop];
        [self dispatchCompletionBlock:error URL:endURL];
    }
    else
    {
        return NO;
    }
    
    [self setWindowController:nil];
    [self setAuthenticationWebViewController:nil];

	return YES;
}


// The user cancelled authentication
- (void)webAuthenticationDidCancel
{
    DebugLog();
    
    // Dispatch the completion block

    ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation];
    [self endWebAuthenticationWithError:error orURL:nil];
}

// Authentication completed at the end URL
- (void)webAuthenticationDidCompleteWithURL:(NSURL *)endURL
{
    DebugLog();
    [self endWebAuthenticationWithError:nil orURL:endURL];
}

// Authentication failed somewhere
- (void)webAuthenticationDidFailWithError:(NSError *)error
{
    // Dispatch the completion block
    ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription];
    
    [self endWebAuthenticationWithError:adError orURL:nil];
}

@end

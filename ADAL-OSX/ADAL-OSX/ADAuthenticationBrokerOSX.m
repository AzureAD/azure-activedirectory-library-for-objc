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

#import "ADOAuth2Constants.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationDelegate.h"
#import "ADAuthenticationWindowController.h"
#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationSettings.h"
#import "ADNTLMHandler.h"


NSString *const AD_FAILED_NO_CONTROLLER = @"The Application does not have a current view controller";
NSString *const AD_FAILED_NO_RESOURCES  = @"The required resource bundle could not be loaded. Please read read the ADALiOS readme on how to build your application with ADAL provided authentication UI resources.";


// Private interface declaration
@interface ADAuthenticationBroker () <ADAuthenticationDelegate>

@end

@implementation ADAuthenticationBroker

+ (ADAuthenticationBroker *)sharedInstance
{
    static ADAuthenticationBroker *broker    = nil;
    static dispatch_once_t         predicate = 0;
    
    dispatch_once( &predicate, ^{
        broker = [[self allocPrivate] init];
    });
    
    return broker;
}

+ (id)alloc
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

+ (id)allocPrivate
{
    return [super alloc];
}

- (id)copy
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)mutableCopy
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

-(NSURL*) addToURL: (NSURL*) url
     correlationId: (NSUUID*) correlationId
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@",
                                 [url absoluteString], OAUTH2_CORRELATION_ID_REQUEST_VALUE, [correlationId UUIDString]]];
}

- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
parentController:(ViewController *)parent
      webView:(WebViewType*)webView
   fullScreen:(BOOL)fullScreen
correlationId:(NSUUID *)correlationId
   completion:(ADBrokerCallback)completionBlock
{
#pragma unused(fullScreen)
#pragma unused(parent)
    THROW_ON_NIL_ARGUMENT(startURL);
    THROW_ON_NIL_ARGUMENT(endURL);
    THROW_ON_NIL_ARGUMENT(correlationId);
    THROW_ON_NIL_ARGUMENT(completionBlock)
    
    _authenticationWebViewController    = nil;
    _authenticationPageController       = nil;
    _authenticationSession              = NULL;
    _ntlmSession    = NO;
    
    startURL = [self addToURL:startURL correlationId:correlationId];//Append the correlation id
    
    // Save the completion block
    _completionBlock = SAFE_ARC_BLOCK_COPY(completionBlock);
    ADAuthenticationError* error = nil;
    
    if (webView)
    {
        // Use the application provided WebView
        _authenticationWebViewController = [[ADAuthenticationWebViewController alloc] initWithWebView:webView startAtURL:startURL endAtURL:endURL];
        
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
        _ntlmSession = [ADNTLMHandler startWebViewNTLMHandlerWithError:nil];
        if (_ntlmSession)
        {
            AD_LOG_INFO(@"Authorization UI", @"Starting NTLM handler.");
        }
        
        // Load the authentication view
        _authenticationPageController = [[ADAuthenticationWindowController alloc] initAtURL:startURL
                                                                                   endAtURL:endURL];
        
        if ( _authenticationPageController )
        {
            _authenticationPageController.delegate = self;
            
            // Start the modal session
            _authenticationSession = [NSApp beginModalSessionForWindow:[_authenticationPageController window]];
            if (_authenticationSession)
            {
                // Initialize the web view controller
                [_authenticationPageController start];
                
                NSDate   *beforeDate = [NSDate date];
                NSInteger result = NSRunContinuesResponse;
                
                // Loop until window is endModal is called
                while ( result == NSRunContinuesResponse )
                {
                    result = [NSApp runModalSession:_authenticationSession];
                    
                    beforeDate = [beforeDate dateByAddingTimeInterval:300];
                    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:beforeDate];
                }
                
                // End the modal session
                [NSApp endModalSession:_authenticationSession];
                
                _authenticationSession = NULL;
            }
            else
            {
                error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MISSING_RESOURCES
                                                               protocolCode:nil
                                                               errorDetails:AD_FAILED_NO_RESOURCES];
            }
        }
        else
        {
            error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MISSING_RESOURCES
                                                           protocolCode:nil
                                                           errorDetails:AD_FAILED_NO_RESOURCES];
        }
    }
    //Error occurred above. Dispatch the callback to the caller:
    if (error)
    {
        [self dispatchCompletionBlock:error URL:nil];
    }
    
    if ( _authenticationPageController )
    {
        SAFE_ARC_RELEASE(_authenticationPageController);
        _authenticationPageController = nil;
    }
}

- (void)cancel
{
    [self webAuthenticationDidCancel];
}

- (void)dispatchCompletionBlock:(ADAuthenticationError *)error URL:(NSURL *)url
{
    // NOTE: It is possible that race between a successful completion
    //       and the user cancelling the authentication dialog can
    //       occur causing this method to be called twice. The race
    //       cannot be blocked at its root, and so this method must
    //       be resilient to this condition and should not generate
    //       two callbacks.
    @synchronized(self)
    {
        if (_ntlmSession)
        {
            [ADNTLMHandler endWebViewNTLMHandler];
        }
        
        if ( _completionBlock )
        {
            void (^completionBlock)( ADAuthenticationError *, NSURL *) = _completionBlock; _completionBlock = nil;
            
            dispatch_async( [ADAuthenticationSettings sharedInstance].dispatchQueue, ^{
                completionBlock( error, url );
            });
            
            SAFE_ARC_BLOCK_RELEASE(completionBlock);
        }
    }
}

// The user cancelled authentication
- (void)webAuthenticationDidCancel
{
    @synchronized(self)//Prevent running between cancellation and navigation
    {
        DebugLog();
        
        // Dispatch the completion block
        
        ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation];
        
        // Dismiss the authentication view if active
        if ( _authenticationSession )
        {
            [NSApp stopModal];
        }
        
        if ( _authenticationPageController )
        {
            [_authenticationPageController close];
            SAFE_ARC_RELEASE(_authenticationPageController); _authenticationPageController = nil;
        }
        
        [_authenticationWebViewController stop];
        SAFE_ARC_RELEASE(_authenticationWebViewController); _authenticationWebViewController = nil;
        
        // Dispatch the completion block
        [self dispatchCompletionBlock:error URL:nil];
    }
}

// Authentication completed at the end URL
- (void)webAuthenticationDidCompleteWithURL:(NSURL *)endURL
{
    @synchronized(self)//Prevent running between navigation and cancellation
    {
        DebugLog();
        
        // Dismiss the authentication view if active
        if ( _authenticationSession )
        {
            [NSApp stopModal];
        }
        
        if ( _authenticationPageController )
        {
            [_authenticationPageController close];
            SAFE_ARC_RELEASE(_authenticationPageController); _authenticationPageController = nil;
        }
        
        [_authenticationWebViewController stop];
        SAFE_ARC_RELEASE(_authenticationWebViewController); _authenticationWebViewController = nil;
        
        [self dispatchCompletionBlock:nil URL:endURL];
    }
}

// Authentication failed somewhere
- (void)webAuthenticationDidFailWithError:(NSError *)error
{
    @synchronized(self)//Prevent running between navigation and cancellation
    {
        // Dispatch the completion block
        ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription];
        
        // Dismiss the authentication view if active
        if ( _authenticationSession )
        {
            [NSApp stopModal];
        }
        
        if ( _authenticationPageController )
        {
            [_authenticationPageController close];
            SAFE_ARC_RELEASE(_authenticationPageController); _authenticationPageController = nil;
        }
        
        [_authenticationWebViewController stop];
        SAFE_ARC_RELEASE(_authenticationWebViewController); _authenticationWebViewController = nil;
        
        // Dispatch the completion block
        [self dispatchCompletionBlock:adError URL:nil];
    }
}


@end

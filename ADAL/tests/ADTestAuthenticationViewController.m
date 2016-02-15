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

#import "ADTestAuthenticationViewController.h"
#import "ADWebAuthDelegate.h"

#pragma mark -
#pragma mark Overriding ADAuthenticationViewController for the test mock
@implementation ADAuthenticationViewController (TestWebviewOverride)

- (id)init
{
    return (ADAuthenticationViewController*)[[ADTestAuthenticationViewController alloc] init];
}

@end

typedef enum
{
    WEB_AUTH_DID_CANCEL_CALL,
    WEB_AUTH_DID_START_LOAD_CALL,
    WEB_AUTH_DID_FINISH_LOAD_CALL,
    WEB_AUTH_SHOULD_START_LOAD_REQUEST_CALL,
    WEB_AUTH_DID_COMPLETE_WITH_URL_CALL,
    WEB_AUTH_DID_FAIL_WITH_ERROR_CALL
} DelegateCallType;

@interface WebAuthDelegateCall : NSObject
{
@public
    DelegateCallType _type;
    id _parameter;
    
}
@end

@implementation WebAuthDelegateCall

- (id)initWithCallType:(DelegateCallType) type
             parameter:(id) parameter
{
    self = [super init];
    if (self)
    {
        _type = type;
        _parameter = [parameter copy];
        SAFE_ARC_RELEASE(_parameter);
    }
    return self;
}

@end


@implementation ADTestAuthenticationViewController

static NSMutableArray<WebAuthDelegateCall*> * s_delegateCalls = nil;

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error
{
    (void) error;
    return YES;
}

- (void)startRequest:(NSURLRequest *)request
{
    [self loadRequest:request];
}

- (void)loadRequest:(NSURLRequest *)request
{
    (void) request;
    for (WebAuthDelegateCall* call in s_delegateCalls)
    {
        [self makeDelegateCall:call];
    }
}

- (void)stop:(void (^)(void))completion
{
    _delegate = nil;
    completion();
}

- (void)startSpinner
{
    return;
}

- (void)stopSpinner
{
    return;
}

- (void)makeDelegateCall:(WebAuthDelegateCall*) call
{
    if (!call)
    {
        return;
    }
    
    switch (call->_type) {
        case WEB_AUTH_DID_CANCEL_CALL:
            [_delegate webAuthDidCancel];
            break;
        case WEB_AUTH_DID_START_LOAD_CALL:
            if ([call->_parameter isKindOfClass:[NSURL class]])
            {
                [_delegate webAuthDidStartLoad:call->_parameter];
            }
            break;
        case WEB_AUTH_DID_FINISH_LOAD_CALL:
            if ([call->_parameter isKindOfClass:[NSURL class]])
            {
                [_delegate webAuthDidFinishLoad:call->_parameter];
            }
            break;
        case WEB_AUTH_SHOULD_START_LOAD_REQUEST_CALL:
            if ([call->_parameter isKindOfClass:[NSURLRequest class]])
            {
                [_delegate webAuthShouldStartLoadRequest:call->_parameter];
            }
            break;
        case WEB_AUTH_DID_COMPLETE_WITH_URL_CALL:
            if ([call->_parameter isKindOfClass:[NSURL class]])
            {
                [_delegate webAuthDidCompleteWithURL:call->_parameter];
            }
            break;
        case WEB_AUTH_DID_FAIL_WITH_ERROR_CALL:
            if ([call->_parameter isKindOfClass:[NSError class]])
            {
                [_delegate webAuthDidFailWithError:call->_parameter];
            }
            break;
        default:
            break;
    }
}

- (void)setDelegate: (id<ADWebAuthDelegate>) delegate
{
    // delegate supposed to be a weak pointer
    _delegate = delegate;
}

#if TARGET_OS_IPHONE
- (void)setWebView: (UIWebView *) webView
{
    (void) webView;
    return;
}

- (void)setParentController:(UIViewController *) parentController
{
    (void) parentController;
}

- (void)setFullScreen: (BOOL) fullScreen
{
    (void) fullScreen;
}
#else
- (void)setWebView: (WebView *) webView
{
    (void) webView;
}
#endif

+ (void)initialize
{
    s_delegateCalls = [NSMutableArray<WebAuthDelegateCall*> new];
}

#pragma mark -
#pragma mark Methods to add delegate calls to the mocking ADTestAuthenticationViewController
+ (void)addDelegateCallWebAuthDidCancel
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_CANCEL_CALL
                                                                    parameter:nil];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

+ (void)addDelegateCallWebAuthDidStartLoad:(NSURL*)url
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_START_LOAD_CALL
                                                                    parameter:url];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

+ (void)addDelegateCallWebAuthDidFinishLoad:(NSURL*)url
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_FINISH_LOAD_CALL
                                                                    parameter:url];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

+ (void)addDelegateCallWebAuthShouldStartLoadRequest:(NSURLRequest*)request
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_SHOULD_START_LOAD_REQUEST_CALL
                                                                    parameter:request];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

+ (void)addDelegateCallWebAuthDidCompleteWithURL:(NSURL *)endURL
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_COMPLETE_WITH_URL_CALL
                                                                    parameter:endURL];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

+ (void)addDelegateCallWebAuthDidFailWithError:(NSError *)error
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_FAIL_WITH_ERROR_CALL parameter:error];
    [s_delegateCalls addObject:call];
    SAFE_ARC_RELEASE(call);
}

@end
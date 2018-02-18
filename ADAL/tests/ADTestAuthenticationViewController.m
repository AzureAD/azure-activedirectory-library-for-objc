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
    }
    return self;
}

@end


@implementation ADTestAuthenticationViewController

static NSMutableArray<WebAuthDelegateCall*> * s_delegateCalls = nil;
static OnLoadBlock s_onLoadBlock = nil;

+ (void)onLoadRequest:(OnLoadBlock)onLoadBlock
{
    s_onLoadBlock = onLoadBlock;
}

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
    if (s_onLoadBlock)
    {
        s_onLoadBlock(request, _delegate);
        s_onLoadBlock = nil;
        return;
    }
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
}

+ (void)addDelegateCallWebAuthDidStartLoad:(NSURL*)url
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_START_LOAD_CALL
                                                                    parameter:url];
    [s_delegateCalls addObject:call];
}

+ (void)addDelegateCallWebAuthDidFinishLoad:(NSURL*)url
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_FINISH_LOAD_CALL
                                                                    parameter:url];
    [s_delegateCalls addObject:call];
}

+ (void)addDelegateCallWebAuthShouldStartLoadRequest:(NSURLRequest*)request
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_SHOULD_START_LOAD_REQUEST_CALL
                                                                    parameter:request];
    [s_delegateCalls addObject:call];
}

+ (void)addDelegateCallWebAuthDidCompleteWithURL:(NSURL *)endURL
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_COMPLETE_WITH_URL_CALL
                                                                    parameter:endURL];
    [s_delegateCalls addObject:call];
}

+ (void)addDelegateCallWebAuthDidFailWithError:(NSError *)error
{
    WebAuthDelegateCall* call = [[WebAuthDelegateCall alloc] initWithCallType:WEB_AUTH_DID_FAIL_WITH_ERROR_CALL parameter:error];
    [s_delegateCalls addObject:call];
}

+ (void)clearDelegateCalls
{
    [s_delegateCalls removeAllObjects];
}

@end

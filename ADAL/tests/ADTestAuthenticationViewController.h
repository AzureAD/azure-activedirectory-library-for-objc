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

#import "ADAL_Internal.h"
#import "ADAuthenticationViewController.h"

typedef void (^OnLoadBlock)(NSURLRequest *urlRequest, id<ADWebAuthDelegate> delegate);

/*! This mock ADAuthenticationViewController has the same set of public properties and functions.*/
@interface ADTestAuthenticationViewController : NSObject
{
    id<ADWebAuthDelegate> _delegate;
#if TARGET_OS_IPHONE
    UIWebView * _webView;
    UIViewController * _parentController;
    BOOL _fullScreen;
#else
    WebView * _webView;
#endif
}

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error;
- (void)startRequest:(NSURLRequest *)request;
- (void)loadRequest:(NSURLRequest *)request;
- (void)stop:(void (^)(void))completion;
- (void)startSpinner;
- (void)stopSpinner;

+ (void)onLoadRequest:(OnLoadBlock)onLoadBlock;

// Following methods are used to add ADWebAuthDelegate calls to the queue
// All calls added in the queue will be called in order when method [loadRequest:] is executed
// Unit test code can use the following methods to simulate how delegate calls are made in ADAuthenticationViewController
+ (void)addDelegateCallWebAuthDidCancel;
+ (void)addDelegateCallWebAuthDidStartLoad:(NSURL*)url;
+ (void)addDelegateCallWebAuthDidFinishLoad:(NSURL*)url;
+ (void)addDelegateCallWebAuthShouldStartLoadRequest:(NSURLRequest*)request;
+ (void)addDelegateCallWebAuthDidCompleteWithURL:(NSURL *)endURL;
+ (void)addDelegateCallWebAuthDidFailWithError:(NSError *)error;
+ (void)clearDelegateCalls;
+ (void)reset;

@end

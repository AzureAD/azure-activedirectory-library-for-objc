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

#import "ADAL_Internal.h"
#import "ADAuthenticationViewController.h"



/*! This mock ADAuthenticationViewController has the same set of public properties and functions.*/
@interface ADTestAuthenticationViewController : NSObject

// same set of public properties and functions as ADAuthenticationViewController
@property (weak, nonatomic) id<ADWebAuthDelegate>     delegate;
#if TARGET_OS_IPHONE
@property (weak, nonatomic) UIWebView * webView;
@property (weak, nonatomic) UIViewController * parentController;
@property BOOL fullScreen;
#else
@property (weak, nonatomic) WebView * webView;
#endif
- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error;
- (void)startRequest:(NSURLRequest *)request;
- (void)loadRequest:(NSURLRequest *)request;
- (void)stop:(void (^)(void))completion;
- (void)startSpinner;
- (void)stopSpinner;

// Following methods are used to add ADWebAuthDelegate calls to the queue
// All calls added in the queue will be called in order when method [loadRequest:] is executed
// Unit test code can use the following methods to simulate how delegate calls are made in ADAuthenticationViewController
+ (void)addDelegateCallWebAuthDidCancel;
+ (void)addDelegateCallWebAuthDidStartLoad:(NSURL*)url;
+ (void)addDelegateCallWebAuthDidFinishLoad:(NSURL*)url;
+ (void)addDelegateCallWebAuthShouldStartLoadRequest:(NSURLRequest*)request;
+ (void)addDelegateCallWebAuthDidCompleteWithURL:(NSURL *)endURL;
+ (void)addDelegateCallWebAuthDidFailWithError:(NSError *)error;

@end
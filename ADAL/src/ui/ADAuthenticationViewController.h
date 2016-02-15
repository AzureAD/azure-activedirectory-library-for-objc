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

@protocol ADWebAuthDelegate;

@interface ADAuthenticationViewController :
#if TARGET_OS_IPHONE
UIViewController
#else
NSWindowController
{
    // In the legacy ObjC runtime (which is what we're stuck at for 32-bit Mac builds)
    // you can't define the ivars of a class in the implementation file.
    __weak id<ADWebAuthDelegate> _delegate;
    __weak WebViewType* _webView;
    __weak NSProgressIndicator* _progressIndicator;
}
#endif

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

@end

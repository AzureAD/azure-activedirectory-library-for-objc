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

#import <Foundation/Foundation.h>
#import "ADAuthenticationContext.h"

@protocol ADWebViewDelegate <NSObject>

- (BOOL)shouldStartLoadWithRequest:(NSURLRequest *)request;
- (void)didStartLoad;
- (void)didFinishLoad;
- (void)didFailLoadWithError:(NSError*)error;

@end

@interface ADWebViewController : NSObject

@property (retain) id<ADWebViewDelegate> delegate;

- (id)initWithWebView:(ADWebView*)webView;
- (void)setDelegate:(id<ADWebViewDelegate>)delegate;

- (void)loadRequest:(NSURLRequest*)request;

@end

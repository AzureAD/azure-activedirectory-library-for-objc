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

#import "ADAutoBaseViewController.h"
#import "ADAutoRequestViewController.h"
#import "ADAutoResultViewController.h"
#import "ADAutoPassedInWebViewController.h"
#import "ADAL.h"
#import "ADTokenCacheDataSource.h"
#import "ADKeychainTokenCache+Internal.h"
#import "MSIDKeychainTokenCache.h"
#import <WebKit/WebKit.h>

@interface ADAutoBaseViewController ()

@end

@implementation ADAutoBaseViewController

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
    if ([segue.identifier isEqualToString:@"showResult"])
    {
        ADAutoResultViewController *resultVC = segue.destinationViewController;
        resultVC.resultInfoString = sender[@"resultInfo"];
        resultVC.resultLogsString = sender[@"resultLogs"];
    }
    
    if ([segue.identifier isEqualToString:@"showRequest"])
    {
        ADAutoRequestViewController *requestVC = segue.destinationViewController;
        requestVC.requestInfo.text = nil;
        requestVC.completionBlock = sender[@"completionHandler"];
    }
    
    if ([segue.identifier isEqualToString:@"showPassedInWebview"])
    {
        ADAutoPassedInWebViewController *requestVC = segue.destinationViewController;
        requestVC.passedInWebview = sender[@"webview"];
    }
}


- (void)showRequestDataViewWithCompletionHandler:(ADAutoParamBlock)completionHandler
{
    [self performSegueWithIdentifier:@"showRequest"
                              sender:@{@"completionHandler":completionHandler}];
}


- (void)showResultViewWithResult:(NSString *)resultJson logs:(NSString *)resultLogs
{
    if (self.presentedViewController)
    {
        [self.presentedViewController dismissViewControllerAnimated:NO completion:^{
            [self presentResults:resultJson logs:resultLogs];
        }];
    }
    else
    {
        [self presentResults:resultJson logs:resultLogs];
    }
}

- (void)presentResults:(NSString *)resultJson logs:(NSString *)resultLogs
{
    [self performSegueWithIdentifier:@"showResult" sender:@{@"resultInfo":resultJson ? resultJson : @"",
                                                            @"resultLogs":resultLogs ? resultLogs : @""}];
}

- (void)showPassedInWebViewControllerWithContext:(ADAuthenticationContext *)context
{
    context.webView = self.webView;
    
    [self.webView loadHTMLString:@"<html><head></head><body>Loading...</body></html>" baseURL:nil];
    [self performSegueWithIdentifier:@"showPassedInWebview" sender:@{@"context" : context,
                                                                     @"webview" : self.webView
                                                                     }];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.webView = [[WKWebView alloc] init];
    self.webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    
}

- (id<ADTokenCacheDataSource>)cacheDatasource
{
    return [ADKeychainTokenCache new];
}

- (void)clearCache
{
    [[MSIDKeychainTokenCache new] clearWithContext:nil error:nil];
}

- (void)clearKeychain
{
    NSArray *secItemClasses = @[(__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecClassInternetPassword,
                                (__bridge id)kSecClassCertificate,
                                (__bridge id)kSecClassKey,
                                (__bridge id)kSecClassIdentity];

    for (NSString *itemClass in secItemClasses)
    {
        NSDictionary *clearQuery = @{(id)kSecClass : (id)itemClass};
        SecItemDelete((CFDictionaryRef)clearQuery);
    }
}

- (void)openURL:(NSURL *)url
{
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
}

@end

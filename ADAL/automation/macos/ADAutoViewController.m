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

#import "ADAutoViewController.h"
#import "ADAutoRequestViewController.h"
#import "ADAutoResultViewController.h"
#import "ADAL.h"
#import "ADTokenCacheDataSource.h"
#import "ADTokenCache.h"
#import "ADTokenCache+Internal.h"
#import "ADAutoWebViewController.h"

@interface ADAutoViewController ()

@end

@implementation ADAutoViewController

- (void)showActionSelectionView
{
    [self selectTabViewAtIndex:0];
}

- (void)showRequestDataViewWithCompletionHandler:(ADAutoParamBlock)completionHandler
{
    [self selectTabViewAtIndex:1];
    ADAutoRequestViewController *requestController = (ADAutoRequestViewController *) [self viewControllerAtIndex:1];
    requestController.completionBlock = completionHandler;
    requestController.requestInfo.string = @"";
}

- (void)showResultViewWithResult:(NSString *)resultJson logs:(NSString *)resultLogs
{
    [self selectTabViewAtIndex:2];
    ADAutoResultViewController *resultController = (ADAutoResultViewController *) [self viewControllerAtIndex:2];
    resultController.resultInfoString = resultJson;
    resultController.resultLogsString = resultLogs;
}

- (void)selectTabViewAtIndex:(NSUInteger)index
{
    NSTabViewController *tabViewController = (NSTabViewController *) self.parentViewController;
    tabViewController.selectedTabViewItemIndex = index;
}

- (NSViewController *)viewControllerAtIndex:(NSUInteger)index
{
    NSTabViewController *tabViewController = (NSTabViewController *) self.parentViewController;
    return tabViewController.tabViewItems[index].viewController;
}

- (void)showPassedInWebViewControllerWithContext:(ADAuthenticationContext *)context
{
    [self selectTabViewAtIndex:3];
    ADAutoWebViewController *webViewController = (ADAutoWebViewController *) [self viewControllerAtIndex:3];
    [context setWebView:webViewController.webView];
    self.webViewController = webViewController;
}

- (void)dismissPassedInWebViewController
{
    self.webViewController = nil;
}

- (id<ADTokenCacheDataSource>)cacheDatasource
{
    return [ADTokenCache defaultCache];
}

- (void)clearCache
{
    [[ADTokenCache defaultCache].macTokenCache clear];
}

- (void)clearKeychain
{
    [[ADTokenCache defaultCache].macTokenCache clear];
}

- (void)openURL:(NSURL *)url
{
    [[NSWorkspace sharedWorkspace] openURL:url];
}

@end

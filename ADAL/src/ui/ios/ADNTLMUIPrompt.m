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

#import "ADNTLMUIPrompt.h"
#import "ADAppExtensionUtil.h"
#import "ADWebAuthController+Internal.h"
#import "ADAuthenticationViewController.h"
#import "ADALFrameworkUtils.h"
#import "UIApplication+ADExtensions.h"

@implementation ADNTLMUIPrompt

__weak static UIAlertController *_presentedPrompt = nil;

+ (void)dismissPrompt
{
    dispatch_async(dispatch_get_main_queue(), ^{
        
        if (_presentedPrompt.presentingViewController)
        {
            [_presentedPrompt.presentingViewController dismissViewControllerAnimated:YES completion:nil];
        }
        
        _presentedPrompt = nil;
    });
}

+ (void)presentPrompt:(void (^)(NSString * username, NSString * password))block
{
    
    if ([ADAppExtensionUtil isExecutingInAppExtension])
    {
        block(nil, nil);
        return;
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController* viewController = [UIApplication adCurrentViewController];
        if (!viewController)
        {
            block(nil, nil);
            return;
        }
        
        NSBundle* bundle = [ADALFrameworkUtils frameworkBundle];
        
        NSString* title = NSLocalizedStringFromTableInBundle(@"Enter your credentials", nil, bundle, nil);
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:nil
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* cancelAction =
        [UIAlertAction actionWithTitle:NSLocalizedStringFromTableInBundle(@"Cancel", nil, bundle, nil)
                                 style:UIAlertActionStyleCancel
                               handler:^(UIAlertAction * _Nonnull action)
         {
             (void)action;
             block(nil, nil);
         }];
        
        UIAlertAction* loginAction =
        [UIAlertAction actionWithTitle:NSLocalizedStringFromTableInBundle(@"Login", nil, bundle, nil)
                                 style:UIAlertActionStyleDefault
                               handler:^(UIAlertAction * _Nonnull action)
         {
             (void)action;
             UITextField* username = alert.textFields.firstObject;
             UITextField* password = alert.textFields.lastObject;
             
             block(username.text, password.text);
         }];
        
        [alert addAction:cancelAction];
        [alert addAction:loginAction];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) { (void)textField; }];
        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
            textField.secureTextEntry = YES;
        }];
        
        [viewController presentViewController:alert animated:YES completion:^{}];
        
        _presentedPrompt = alert;
    });
}

@end

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

#import <objc/runtime.h>

#import "ADALBrokerHelper.h"
#import "ADALBrokerNotificationManager.h"
#import "ADALWebAuthController+Internal.h"
#import "ADALAppExtensionUtil.h"
#import "ADALAuthenticationContext+Internal.h"
#import "MSIDMainThreadUtil.h"

typedef BOOL (*applicationHandleOpenURLPtr)(id, SEL, UIApplication*, NSURL*);
IMP __original_ApplicationHandleOpenURL = NULL;

typedef BOOL (*applicationOpenURLPtr)(id, SEL, UIApplication*, NSURL*, NSString*, id);
IMP __original_ApplicationOpenURL = NULL;

BOOL __swizzle_ApplicationOpenURL(id self, SEL _cmd, UIApplication* application, NSURL* url, NSString* sourceApplication, id annotation)
{
    if ([ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApplication])
    {
        // Attempt to handle response from broker
        BOOL result = [ADALAuthenticationContext handleBrokerResponse:url sourceApplication:sourceApplication];

        if (result)
        {
            // Successfully handled broker response
            return YES;
        }
    }
    
    MSID_LOG_INFO(nil, @"This url cannot be handled by ADAL. Skipping it.");

    // Fallback to original delegate if defined
    if (__original_ApplicationOpenURL)
    {
        return ((applicationOpenURLPtr)__original_ApplicationOpenURL)(self, _cmd, application, url, sourceApplication, annotation);
    }
    else if (__original_ApplicationHandleOpenURL)
    {
        return ((applicationHandleOpenURLPtr)__original_ApplicationHandleOpenURL)(self, @selector(application:handleOpenURL:), application, url);
    }
    else
    {
        return NO;
    }
}

typedef BOOL (*applicationOpenURLiOS9Ptr)(id, SEL, UIApplication*, NSURL*, NSDictionary<NSString*, id>*);
IMP __original_ApplicationOpenURLiOS9 = NULL;

BOOL __swizzle_ApplicationOpenURLiOS9(id self, SEL _cmd, UIApplication* application, NSURL* url, NSDictionary<NSString*, id>* options)
{
    NSString* sourceApplication = [options objectForKey:UIApplicationOpenURLOptionsSourceApplicationKey];

    if ([ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApplication])
    {
        // Attempt to handle response from broker
        BOOL result = [ADALAuthenticationContext handleBrokerResponse:url sourceApplication:sourceApplication];

        if (result)
        {
            // Successfully handled broker response
            return YES;
        }
    }
    
    MSID_LOG_INFO(nil, @"This url cannot be handled by ADAL. Skipping it.");

    // Fallback to original delegate if defined
    if (__original_ApplicationOpenURLiOS9)
    {
        return ((applicationOpenURLiOS9Ptr)__original_ApplicationOpenURLiOS9)(self, _cmd, application, url, options);
    }
    else if (__original_ApplicationHandleOpenURL)
    {
        return ((applicationHandleOpenURLPtr)__original_ApplicationHandleOpenURL)(self, @selector(application:handleOpenURL:), application, url);
    }
    else
    {
        return NO;
    }
}

@implementation ADALBrokerHelper

// If we are in the broker, do not intercept openURL calls
#if !AD_BROKER
+ (void)load
{
    if ([ADALAppExtensionUtil isExecutingInAppExtension])
    {
        // Avoid any setup in application extension hosts
        return;
    }

    __block __weak id observer = nil;
    
    observer =
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification* notification)
     {
         (void)notification;
         // We don't want to swizzle multiple times so remove the observer
         [[NSNotificationCenter defaultCenter] removeObserver:observer name:UIApplicationDidFinishLaunchingNotification object:nil];
         
         SEL sel = @selector(application:openURL:sourceApplication:annotation:);
         SEL seliOS9 = @selector(application:openURL:options:);
         SEL handleOpenURLSel = @selector(application:handleOpenURL:);
         
         // Dig out the app delegate (if there is one)
         __strong id appDelegate = [[ADALAppExtensionUtil sharedApplication] delegate];
         
         // There's not much we can do if there's no app delegate and there might be scenarios where
         // that is valid...
         if (appDelegate == nil)
             return;
         
         // Support applications which implement handleOpenURL to handle URL requests.
         // An openURL method will be added to the application's delegate, but the request will be
         // forwarded to the application's handleOpenURL: method once handled by ADAL.
         if ([appDelegate respondsToSelector:handleOpenURLSel])
         {
             Method m = class_getInstanceMethod([appDelegate class], handleOpenURLSel);
             __original_ApplicationHandleOpenURL = method_getImplementation(m);
         }
         
         BOOL iOS9OrGreater = [[[UIDevice currentDevice] systemVersion] intValue] >= 9;
         
         if ([appDelegate respondsToSelector:seliOS9] && iOS9OrGreater)
         {
             Method m = class_getInstanceMethod([appDelegate class], seliOS9);
             __original_ApplicationOpenURLiOS9 = method_getImplementation(m);
             method_setImplementation(m, (IMP)__swizzle_ApplicationOpenURLiOS9);
         }
         else if ([appDelegate respondsToSelector:sel])
         {
             Method m = class_getInstanceMethod([appDelegate class], sel);
             __original_ApplicationOpenURL = method_getImplementation(m);
             method_setImplementation(m, (IMP)__swizzle_ApplicationOpenURL);
         }
         else if (iOS9OrGreater)
         {
             NSString* typeEncoding = [NSString stringWithFormat:@"%s%s%s%s%s%s", @encode(BOOL), @encode(id), @encode(SEL), @encode(UIApplication*), @encode(NSURL*), @encode(NSDictionary<NSString*, id>*)];
             class_addMethod([appDelegate class], seliOS9, (IMP)__swizzle_ApplicationOpenURLiOS9, [typeEncoding UTF8String]);
             
             // UIApplication caches whether or not the delegate responds to certain selectors. Clearing out the delegate and resetting it gaurantees that gets updated
             [[ADALAppExtensionUtil sharedApplication] setDelegate:nil];
             // UIApplication employs dark magic to assume ownership of the app delegate when it gets the app delegate at launch, it won't do that for setDelegate calls so we
             // have to add a retain here to make sure it doesn't turn into a zombie
             [[ADALAppExtensionUtil sharedApplication] setDelegate:(__bridge id)CFRetain((__bridge CFTypeRef)appDelegate)];
         }
         else
         {
             NSString* typeEncoding = [NSString stringWithFormat:@"%s%s%s%s%s%s%s", @encode(BOOL), @encode(id), @encode(SEL), @encode(UIApplication*), @encode(NSURL*), @encode(NSString*), @encode(id)];
             class_addMethod([appDelegate class], sel, (IMP)__swizzle_ApplicationOpenURL, [typeEncoding UTF8String]);
             
             // UIApplication caches whether or not the delegate responds to certain selectors. Clearing out the delegate and resetting it gaurantees that gets updated
             [[ADALAppExtensionUtil sharedApplication] setDelegate:nil];
             // UIApplication employs dark magic to assume ownership of the app delegate when it gets the app delegate at launch, it won't do that for setDelegate calls so we
             // have to add a retain here to make sure it doesn't turn into a zombie
             [[ADALAppExtensionUtil sharedApplication] setDelegate:(__bridge id)CFRetain((__bridge CFTypeRef)appDelegate)];
         }
     }];
}
#endif

+ (BOOL)canUseBroker
{
    if (![NSThread isMainThread])
    {
        __block BOOL result = NO;
        dispatch_sync(dispatch_get_main_queue(), ^{
            result = [self canUseBroker];
        });
        
        return result;
    }
    
    if (![ADALAppExtensionUtil isExecutingInAppExtension])
    {
        BOOL brokerPresent = [[ADALAppExtensionUtil sharedApplication] canOpenURL:[[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker", ADAL_BROKER_SCHEME]]];
        
        if (!brokerPresent)
        {
            MSID_LOG_INFO(nil, @"No broker is present on device");
            return NO;
        }
        
        if (@available(iOS 13.0, *))
        {
            BOOL newBrokerPresent = [[ADALAppExtensionUtil sharedApplication] canOpenURL:[[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker", ADAL_BROKER_NONCE_SCHEME]]];
            
            if (!newBrokerPresent)
            {
                MSID_LOG_INFO(nil, @"Broker is present on the device, but it doesn't satisfy minimum required version");
            }
            
            return newBrokerPresent;
        }
        
        return YES;
    }
    else
    {
        // Cannot perform app switching from application extension hosts
        return NO;
    }
}

+ (void)invokeBroker:(NSURL *)brokerURL
   completionHandler:(ADAuthenticationCallback)completion
{
    if ([ADALAppExtensionUtil isExecutingInAppExtension])
    {
        // Ignore invocation in application extension hosts
        ADALAuthenticationError* error = [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_NOT_SUPPORTED_IN_EXTENSION
                                                                              protocolCode:nil
                                                                              errorDetails:@"Calling to broker is not supported in app extensions"
                                                                             correlationId:nil];
        completion([ADALAuthenticationResult resultFromError:error]);
        return;
    }
    
    [[ADALBrokerNotificationManager sharedInstance] enableNotifications:completion];
    
    [MSIDMainThreadUtil executeOnMainThreadIfNeeded:^{
        [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthWillSwitchToBrokerApp object:nil];
        [ADALAppExtensionUtil sharedApplicationOpenURL:brokerURL];
    }];
}

+ (void)saveToPasteBoard:(NSURL*) url
{
    UIPasteboard *appPasteBoard = [UIPasteboard pasteboardWithName:@"WPJ"
                                                            create:YES];
    url = [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@", url.absoluteString, @"sourceApplication",[[NSBundle mainBundle] bundleIdentifier]]];
    [appPasteBoard setURL:url];
}

+ (void)promptBrokerInstall:(NSURL *)appInstallLink
              brokerRequest:(NSURL *)brokerRequest
          completionHandler:(ADAuthenticationCallback)completion
{
    if ([ADALAppExtensionUtil isExecutingInAppExtension])
    {
        // Ignore invocation in application extension hosts
        completion(nil);
        return;
    }
    
    if (!appInstallLink)
    {
        ADALAuthenticationError *error = [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                                              protocolCode:nil
                                                                              errorDetails:[NSString stringWithFormat:@"appInstallLink is not valid - %@", appInstallLink.absoluteString]
                                                                                  userInfo:nil
                                                                             correlationId:nil];
        
        ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromError:error correlationId:nil];
        completion(result);
        return;
    }

    [[ADALBrokerNotificationManager sharedInstance] enableNotifications:completion];
    [self saveToPasteBoard:brokerRequest];
    
    [MSIDMainThreadUtil executeOnMainThreadIfNeeded:^{
        [ADALAppExtensionUtil sharedApplicationOpenURL:appInstallLink];
    }];
}

+ (ADAuthenticationCallback)copyAndClearCompletionBlock
{
    return [[ADALBrokerNotificationManager sharedInstance] copyAndClearCallback];
}

@end

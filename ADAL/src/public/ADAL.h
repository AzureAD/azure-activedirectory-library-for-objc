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

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif

//! Project version number for ADALFramework.
FOUNDATION_EXPORT double ADALFrameworkVersionNumber;

//! Project version string for ADALFramework.
FOUNDATION_EXPORT const unsigned char ADALFrameworkVersionString[];

#if TARGET_OS_IPHONE
//iOS:
typedef UIWebView WebViewType;
#else
//OS X:
#   include <WebKit/WebKit.h>
typedef WebView   WebViewType;
#endif

@class ADAuthenticationResult;

/*! The completion block declaration. */
typedef void(^ADAuthenticationCallback)(ADAuthenticationResult* result);

#if __has_feature(objc_arc)
#   define SAFE_ARC_PROP_RETAIN strong
#   define SAFE_ARC_RETAIN(x) (x)
#   define SAFE_ARC_RELEASE(x)
#   define SAFE_ARC_AUTORELEASE(x) (x)
#   define SAFE_ARC_BLOCK_COPY(x) (x)
#   define SAFE_ARC_BLOCK_RELEASE(x)
#   define SAFE_ARC_SUPER_DEALLOC()
#   define SAFE_ARC_AUTORELEASE_POOL_START() @autoreleasepool {
#   define SAFE_ARC_AUTORELEASE_POOL_END() }
#   define SAFE_ARC_DISPATCH_RETAIN(x)
#   define SAFE_ARC_DISPATCH_RELEASE(x)
#   define SAFE_ARC_WEAK __weak
#else
#   define SAFE_ARC_PROP_RETAIN retain
#   define SAFE_ARC_RETAIN(x) ([(x) retain])
#   define SAFE_ARC_RELEASE(x) ([(x) release])
#   define SAFE_ARC_AUTORELEASE(x) ([(x) autorelease])
#   define SAFE_ARC_BLOCK_COPY(x) (Block_copy(x))
#   define SAFE_ARC_BLOCK_RELEASE(x) (Block_release(x))
#   define SAFE_ARC_SUPER_DEALLOC() ([super dealloc])
#   define SAFE_ARC_AUTORELEASE_POOL_START() NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
#   define SAFE_ARC_AUTORELEASE_POOL_END() [pool release];
#   define SAFE_ARC_DISPATCH_RETAIN(x) dispatch_retain((x))
#   define SAFE_ARC_DISPATCH_RELEASE(x) dispatch_release((x))
#   define SAFE_ARC_WEAK
# ifdef DEBUG
//Crash the application if messages are sent to the released variable, but only in DEBUG mode
#   define SAFE_ARC_RELEASE(x) { _SAFE_ARC_RELEASE(x); (x) = (id)nil; }
# else
//Set the variable to nil in release mode to avoid crashing, as obj-c allows sending messages to nil pointers:
#   define SAFE_ARC_RELEASE(x) { _SAFE_ARC_RELEASE(x); (x) = nil; }
# endif
#endif


#import <ADAL/ADAuthenticationContext.h>
#import <ADAL/ADAuthenticationError.h>
#import <ADAL/ADAuthenticationParameters.h>
#import <ADAL/ADAuthenticationResult.h>
#import <ADAL/ADAuthenticationSettings.h>
#import <ADAL/ADErrorCodes.h>
#import <ADAL/ADLogger.h>
#import <ADAL/ADTokenCacheItem.h>
#import <ADAL/ADUserIdentifier.h>
#import <ADAL/ADUserInformation.h>
#import <ADAL/ADWebAuthController.h>

#if TARGET_OS_IPHONE
#import <ADAL/ADKeychainTokenCache.h>
#else
#import <ADAL/ADTokenCache.h>
#endif


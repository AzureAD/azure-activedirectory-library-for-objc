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

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif

//! Project version number for ADALiOSFramework.
FOUNDATION_EXPORT double ADALFrameworkVersionNumber;

//! Project version string for ADALiOSFramework.
FOUNDATION_EXPORT const unsigned char ADALFrameworkVersionString[];

#if TARGET_OS_IPHONE
//iOS:
#   include <UIKit/UIKit.h>
typedef UIWebView WebViewType;
#else
//OS X:
#   include <WebKit/WebKit.h>
typedef WebView   WebViewType;
#endif

@class ADAuthenticationResult;

/*! The completion block declaration. */
typedef void(^ADAuthenticationCallback)(ADAuthenticationResult* result);

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


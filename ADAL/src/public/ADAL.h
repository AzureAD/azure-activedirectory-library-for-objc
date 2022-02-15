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

#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif

//! Project version number for ADALFramework.
FOUNDATION_EXPORT double ADALFrameworkVersionNumber;

//! Project version string for ADALFramework.
FOUNDATION_EXPORT const unsigned char ADALFrameworkVersionString[];

@class ADALAuthenticationResult;

/*! The completion block declaration. */
typedef void(^ADAuthenticationCallback)(ADALAuthenticationResult* _Nonnull result);

#import <ADAL/ADALAuthenticationContext.h>
#import <ADAL/ADALAuthenticationContext+RemoteDeviceIdentity.h>
#import <ADAL/ADALAuthenticationError.h>
#import <ADAL/ADALAuthenticationParameters.h>
#import <ADAL/ADALAuthenticationResult.h>
#import <ADAL/ADALAuthenticationSettings.h>
#import <ADAL/ADALErrorCodes.h>
#import <ADAL/ADALLogger.h>
#import <ADAL/ADALTokenCacheItem.h>
#import <ADAL/ADALUserIdentifier.h>
#import <ADAL/ADALUserInformation.h>
#import <ADAL/ADALWebAuthController.h>
#import <ADAL/ADALTelemetry.h>

#if TARGET_OS_IPHONE
#import <ADAL/ADALKeychainTokenCache.h>
#else
#import <ADAL/ADALTokenCache.h>
#endif


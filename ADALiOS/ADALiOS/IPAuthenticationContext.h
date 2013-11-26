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

#pragma once

#if TARGET_OS_IPHONE
    typedef UIWebView SysWebView;
#else
    typedef WebView   SysWebView;
#endif

@class IPAuthenticationContext;
@class IPAuthenticationResult;
@class IPAuthenticationSettings;

typedef void (^AuthorizationCallback)(IPAuthenticationResult *) ;
@class IPAuthorization;

// Interface to the authentication subsystem.
@interface IPAuthenticationContext : NSObject

// Authorization Cache management
+ (IPAuthorization *)authorizationForKey:(NSString *)key;
+ (void)setAuthorization:(IPAuthorization *)authorization forKey:(NSString *)key;
+ (void)removeAuthorizationForKey:(NSString *)key;
+ (void)removeAllAuthorizations;

// OAuth2 Authorization Request using default mechanisms.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)requestAuthorization:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope completion:( AuthorizationCallback )completionBlock;

// OAuth2 Authorization Request using default mechanisms, using a WebView hosted by the application.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)requestAuthorization:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:( AuthorizationCallback )completionBlock;

// This API cancels an outstanding requestAuthorization call.
+ (void)cancelRequestAuthorization;

// Generic OAuth2 Token Request using a Refresh Token
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)refreshAuthorization:(IPAuthorization *)authorization completion:( AuthorizationCallback )completionBlock;

// Generic OAuth2 Authorization + Token Request
// This API will attempt to find a cached Authorization first and refresh it if necessary. If no cached Authorization
// can be found, or the refresh fails, the API will request a new Authorization. In effect, this API is a combination
// of authorizationForKey:, refreshAuthorization:completion: and requestAuthorization:resource:scope:completion.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)requestAccessToken:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:( AuthorizationCallback )completionBlock;

// Gets the settings for the AuthorizationContext
+ (IPAuthenticationSettings *)settings;

@end

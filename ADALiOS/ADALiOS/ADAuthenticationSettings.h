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

@protocol ADTokenCacheStoring;
/*!
 Controls where would the credentials dialog reside
 */
typedef enum
{
    /*!
     The SDK determines automatically the most suitable option, optimized for user experience.
     E.g. it may invoke another application for a single sign on, if such application is present.
     This is the default option.
     */
    AD_CREDENTIALS_AUTO,
    
    /*!
     The SDK will present an embedded dialog within the application. It will not invoke external
     application or browser.
     */
    AD_CREDENTIALS_EMBEDDED,
    
} ADCredentialsType;

/*! The class stores global settings for the ADAL library. It is a singleton class
 and the alloc, init and new should not be called directly. The "sharedInstance" selector
 should be used instead to provide the settings instance.
 */
@interface ADAuthenticationSettings : NSObject

/*! The static instance of the singleton settings class*/
+(ADAuthenticationSettings*) sharedInstance;

/*! See the ADCredentialsType enumeration definition for details */
@property ADCredentialsType credentialsType;

/*! The timeout used for any of the web requests. Specified in seconds. */
@property int requestTimeOut;

/*! When checking an access token for expiration we check if time to expiration
 is less than this value (in seconds) before making the request. The goal is to
 refresh the token ahead of its expiration and also not to return a token that is
 about to expire. */
@property uint expirationBuffer;

/*! Used for the webView. Default is YES.*/
@property BOOL enableFullScreen;

/*! The dispatch queue to be used for the asynchronous calls. */
@property dispatch_queue_t dispatchQueue;

/*! The default token cache store to be used by the ADAuthenticationContext instances. */
@property id<ADTokenCacheStoring> defaultTokenCacheStore;

@end

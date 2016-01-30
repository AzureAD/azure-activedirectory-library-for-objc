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

@class ADAuthenticationError;

#import "ADAuthenticationContext.h"

/*! Fired at the start of a resource load in the webview. The URL of the load, if available, will be in the @"url" key in the userInfo dictionary */
extern NSString* ADWebAuthDidStartLoadNotification;

/*! Fired when a resource finishes loading in the webview. */
extern NSString* ADWebAuthDidFinishLoadNotification;

/*! Fired when web authentication fails due to reasons originating from the network. Look at the @"error" key in the userInfo dictionary for more details.*/
extern NSString* ADWebAuthDidFailNotification;

/*! Fired when authentication finishes */
extern NSString* ADWebAuthDidCompleteNotification;

@interface ADWebAuthController : NSObject

//Cancel the web authentication session which might be happening right now
//Note that it only works if there's an active web authentication session going on
+ (void)cancelCurrentWebAuthSession;

@end

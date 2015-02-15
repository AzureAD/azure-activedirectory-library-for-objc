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
#include <UIKit/UIKit.h>
#import <ADALiOS/ADAuthenticationResult.h>
#import <ADALiOS/ADAuthenticationContext.h>


/*! The completion block declarations. */
typedef void(^ADBrokerCallback)(ADAuthenticationResult* result);
typedef void(^ADOnResultCallback)(BOOL result, NSError* error);
typedef void(^ADAccountListCallback)(NSDictionary* accounts);

@interface ADBrokerContext : NSObject

+ (void) invokeBrokerLocally: (NSString*) requestPayload
             completionBlock: (ADBrokerCallback) completionBlock;

+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
                          completionBlock: (ADBrokerCallback) completionBlock;

// to be used when user invokes add account flow from the app
- (void) acquireAccount:(NSString*) upn
           clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
    completionBlock:(ADBrokerCallback) completionBlock;

- (void) removeAccount: (NSString*) upn
         onResultBlock:(ADOnResultCallback) onResultBlock;

//- (void) isDeviceWpj

@end
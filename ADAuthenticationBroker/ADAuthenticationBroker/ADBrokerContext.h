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
#import <workplaceJoinAPI/RegistrationInformation.h>
#import "ADBrokerPRTContext.h"

@class ADAuthenticationResult;

/*! The completion block declarations. */
typedef void(^ADOnResultCallback)(NSError* error);

@interface ADBrokerContext : NSObject

@property (readonly) NSString* authority;

@property (strong) NSUUID* correlationId;

+ (BOOL) isBrokerRequest: (NSURL*) requestPayloadUrl
               returnUpn: (NSString**) returnUpn;

+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
                                      upn: (NSString*) upn;

+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication;

- (id) initWithAuthority:(NSString*) authority;

// to be used when user invokes add account flow from the app
- (void) acquireAccount:(NSString*) upn
    completionBlock:(ADAuthenticationCallback) completionBlock;

- (void) acquireAccount:(NSString*) upn
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
        completionBlock:(ADAuthenticationCallback) completionBlock;

+ (NSArray*) getAllAccounts:(ADAuthenticationError*) error;

- (void) removeAccount: (NSString*) upn
         onResultBlock:(ADOnResultCallback) onResultBlock;

- (void) doWorkPlaceJoinForUpn: (NSString*) upn
                 onResultBlock:(ADPRTResultCallback) onResultBlock;

+ (RegistrationInformation*) getWorkPlaceJoinInformation;

- (void) removeWorkPlaceJoinRegistration:(ADOnResultCallback) onResultBlock;


@end
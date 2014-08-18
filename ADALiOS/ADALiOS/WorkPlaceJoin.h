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
#import "RegistrationInformation.h"

@class WorkPlaceJoin;

/// WorkPlaceJoin Delegates
/// We have 2 delegates one for success and one for failure
@protocol WorkPlaceJoinDelegate

/// In the event an error ocurred during the discovery, authentication, the
/// didFailJoinWithError delegate is triggered providing the error encountered
/// Errors as a direct results of this API contain error code 200 @domain
/// "WorkPlace Join"
- (void)workplaceClient:(WorkPlaceJoin*)workplaceClient
   didFailJoinWithError:(NSError*)error;

/// If the calling application has set this delegate all logging will go through
/// the delegate.  If it is not set all logging will happen to [WorkPlaceJoinUtil WorkPlaceJoinUtilManager] Log:.
- (void)workplaceClient:(WorkPlaceJoin*)workplaceClient
   logMessage:(NSString*)logMessage;

@end

/*! The completion block declaration for leave */
typedef void(^WorkplaceJoinLeaveCallback)(NSError*);

@interface WorkPlaceJoin : NSObject <NSURLConnectionDelegate>

@property (weak, nonatomic) id <WorkPlaceJoinDelegate> delegate;

/*! Represents the shared access group used by this api. */
@property (readwrite) NSString* sharedGroup;

/// Returns a static instance of the WorkPlaceJoin class which can then be used
/// to perform a join, leave, verify if the device is joined and get the
/// registered UPN in the event the device is joined.
+ (WorkPlaceJoin*) WorkPlaceJoinManager;

/// Will look at the shared application keychain in search for a certificate
/// Certificate found returns true
/// Certificate not found returns false
- (BOOL)isWorkPlaceJoined;

- (RegistrationInformation*) getRegistrationInformation;

@end


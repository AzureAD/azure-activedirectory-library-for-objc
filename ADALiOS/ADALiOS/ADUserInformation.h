// Created by Boris Vidolov on 10/15/13.
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
#import <ADALiOS/ADAuthenticationError.h>

/*! Contains the details about a user that had authorized resource usage*/
@interface ADUserInformation : NSObject<NSCopying, NSSecureCoding>

/* The only initializer. The default initializer will throw unrecognized selector
 exception. Please use this one instead */
+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error;

/* This is the only readonly property, as it is used in the key generation for the cache.
 A new user information object should be created if userId changes */
@property (readonly) NSString* userId;

/*! Determines whether userId is displayable */
@property BOOL userIdDisplayable;

/*! May be null */
@property NSString* givenName;

/*! May be null */
@property NSString* familyName;

/*! May be null */
@property NSString* identityProvider;

@end

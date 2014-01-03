// Created by Boris Vidolov on 12/27/13.
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

@class ADAuthenticationError;

/*! The completion block declaration. */
typedef void(^ADDiscoveryCallback)(BOOL validated, ADAuthenticationError* error);

/*! A singleton class, used to validate authorities with in-memory caching of the previously validated ones.
 The class is thread-safe. */
@interface ADInstanceDiscovery : NSObject
{
    NSMutableSet* mValidatedAuthorities;
}

@property (readonly, getter = getValidatedAuthorities) NSSet* validatedAuthorities;

/*! The shared instance of the class. Attempt to create the class with new or init will throw an exception.*/
+(ADInstanceDiscovery*) sharedInstance;

/*! Validates asynchronously the provided authority. */
-(void) validateAuthority: (NSString*) authority
          completionBlock: (ADDiscoveryCallback) completionBlock;

/*! Takes the string and makes it canonical URL, e.g. lowercase with
 ending trailing "/". If the authority is not a valid URL, the method
 will return nil. */
+(NSString*) canonicalizeAuthority: (NSString*) authority;

@end

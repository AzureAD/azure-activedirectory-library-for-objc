// Created by Boris Vidolov on 10/18/13.
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

/*! Defines the cache store key. The object is immutable and new one should be created each time
 a new key is required. Keys can be created or extracted from existing ADTokenCacheStoreItem objects. */
@interface ADTokenCacheStoreKey : NSObject<NSCopying>
{
    NSUInteger hash;
}

/*! Creates a key
 @param authority: Required. The authentication authority used.
 @param resource: Required. The resource used for the token.
 @param scope: Optional, can be nil. The OAuth2 scope.
 */
+(ADTokenCacheStoreKey*) keyWithAuthority: (NSString*) authority
                                 resource: (NSString*) resource
                                 clientId: (NSString*)clientId
                                    error: (ADAuthenticationError* __autoreleasing*) error;

/*! The authority that issues access tokens */
@property (readonly) NSString* authority;

/*! The resouce to which the access tokens are issued */
@property (readonly) NSString* resource;

/*! The application client identifier */
@property (readonly) NSString* clientId;


@end

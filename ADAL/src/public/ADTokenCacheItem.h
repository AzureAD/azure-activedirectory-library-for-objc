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

@class ADUserInformation;
@class ADTokenCacheKey;
@class ADAuthenticationError;

/*! Contains all cached elements for a given request for a token.
    Objects of this class are used in the key-based token cache store.
    See the key extraction function for details on how the keys are constructed. */
@interface ADTokenCacheItem : NSObject<NSCopying , NSSecureCoding>
{
    NSUInteger _hash;
    NSString* _resource;
    NSString* _authority;
    NSString* _clientId;
    NSString* _accessToken;
    NSString* _accessTokenType;
    NSString* _refreshToken;
    NSData* _sessionKey;
    NSDate* _expiresOn;
    ADUserInformation* _userInformation;
}

/*! Applicable resource. Should be nil, in case the item stores multi-resource refresh token. */
@property (copy) NSString* resource;

@property (copy) NSString* authority;

@property (copy) NSString* clientId;

@property (copy) NSString* familyId;

/*! The access token received. Should be nil, in case the item stores multi-resource refresh token. */
@property (copy) NSString* accessToken;

@property (copy) NSString* accessTokenType;

@property (copy) NSString* refreshToken;

@property (copy) NSData* sessionKey;

@property (copy) NSDate* expiresOn;


@property (retain) ADUserInformation* userInformation;

/*! Obtains a key to be used for the internal cache from the full cache item.
 @param error: if a key cannot be extracted, the method will return nil and if this parameter is not nil,
 it will be filled with the appropriate error information.*/
- (ADTokenCacheKey*) extractKey:(ADAuthenticationError * __autoreleasing *)error;

/*! Compares expiresOn with the current time. If expiresOn is not nil, the function returns the
 comparison of expires on and the current time. If expiresOn is nil, the function returns NO,
 so that the cached token can be tried first.*/
- (BOOL)isExpired;

/*! Returns YES if the user is not not set. */
- (BOOL)isEmptyUser;

/*! Verifies if the user (as defined by userId) is the same between the two items. */
- (BOOL)isSameUser:(ADTokenCacheItem *)other;

/*! If true, the cache store item does not store actual access token, but instead a refresh token that can be
 used to obtain access token for any resource within the same user, authority and client id. This property is calculated
 from the value of other properties: it is true if: resource is nil, accessToken is nil and refresh token is not nil or empty.*/
- (BOOL)isMultiResourceRefreshToken;

@end

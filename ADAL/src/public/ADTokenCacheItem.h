// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
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
    NSString* _familyId;
    NSString* _accessToken;
    NSString* _accessTokenType;
    NSString* _refreshToken;
    NSData* _sessionKey;
    NSDate* _expiresOn;
    ADUserInformation* _userInformation;
	NSMutableDictionary* _tombstone;
    
    // Any extra properties that have been added to ADTokenCacheItem since 2.2,
    // coming from the server that we didn't process, but potentially want to
    // retain to make sure we have as much information as possible,
    NSDictionary* _additionalServer;
    
    // Any extra properties we generate on the client side on an item that we
    // potentially want to make sure don't get clobbered in old versions of ADAL.
    // NOTE: Will get clobbered by versions of ADAL prior to 2.2
    NSMutableDictionary* _additionalClient;
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

/*!
 The item is a tombstone if this property if not nil;
 The dictionary contains the following pairs:
 @"bundleId":Bundle ID of the app which tombstones the token.
 @"correlationId":correlation ID of the request that we got the error from.
 @"protocolCode":error code returned by the server for the rejected RT
  @"errorDetails":error details of the rejected RT
 */
- (NSDictionary*)tombstone;

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

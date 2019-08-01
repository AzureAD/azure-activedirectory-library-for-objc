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
    NSString* _storageAuthority;
    NSString* _clientId;
    NSString* _familyId;
    NSString* _accessToken;
    NSString* _accessTokenType;
    NSString* _refreshToken;
    NSData* _sessionKey;
    NSDate* _expiresOn;
    NSString* _enrollmentId;
    NSString* _applicationIdentifier;
    ADUserInformation* _userInformation;
    
    // Any extra properties that have been added to ADTokenCacheItem since 2.2,
    // coming from the server that we didn't process, but potentially want to
    // retain to make sure we have as much information as possible,
    NSDictionary* _additionalServer;
}

NS_ASSUME_NONNULL_BEGIN

/*! Applicable resource. Should be nil, in case the item stores multi-resource refresh token. */
@property (copy, nullable) NSString* resource;

@property (copy) NSString* authority;

@property (copy, nullable) NSString* clientId;

@property (copy, nullable) NSString* familyId;

/*! The access token received. Should be nil, in case the item stores multi-resource refresh token. */
@property (copy, nullable) NSString* accessToken;

@property (copy, nullable) NSString* accessTokenType;

@property (copy, nullable) NSString* refreshToken;

@property (copy, nullable) NSData* sessionKey;

@property (copy, nullable) NSDate* expiresOn;

@property (retain, nullable) ADUserInformation* userInformation;

/*! Obtains a key to be used for the internal cache from the full cache item.
 @param error If a key cannot be extracted, the method will return nil and if this parameter is not nil,
 it will be filled with the appropriate error information.*/
- (nullable ADTokenCacheKey*)extractKey:(ADAuthenticationError * _Nullable __autoreleasing * _Nullable)error;

/*! Compares expiresOn with the current time. If expiresOn is not nil, the function returns the
 comparison of expires on and the current time. If expiresOn is nil, the function returns NO,
 so that the cached token can be tried first.*/
- (BOOL)isExpired;

/*! Returns YES if the user is not not set. */
- (BOOL)isEmptyUser;

/*! If true, the cache store item does not store actual access token, but instead a refresh token that can be
 used to obtain access token for any resource within the same user, authority and client id. This property is calculated
 from the value of other properties: it is true if: resource is nil, accessToken is nil and refresh token is not nil or empty.*/
- (BOOL)isMultiResourceRefreshToken;

@end

NS_ASSUME_NONNULL_END

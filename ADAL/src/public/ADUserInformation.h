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

@class ADAuthenticationError;
/*! Contains the details about a user that had authorized resource usage*/
@interface ADUserInformation : NSObject<NSCopying, NSSecureCoding>
{
    NSString *_userId;
    BOOL _userIdDisplayable;
    NSString *_uniqueId;
    NSString *_rawIdToken;
    NSDictionary *_allClaims;
    NSString *_homeAccountId;
}

/*! Factory method to extract user information from the AAD id_token parameter.
 @param idToken The contents of the id_token parameter, as passed by the server.
 */
+ (nullable ADUserInformation *)userInformationWithIdToken:(nonnull NSString *)idToken
                                                     error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;

/* This is the only unique property, as it is used in the key generation for the cache.user
 Two ADUserInformation objects are considered the same if this property is the same. Using RequiredDisplayableId
 will validate against this property. */
@property (readonly, nonnull) NSString *userId;

/*! Unique AAD account identifier across tenants based on user's home OID/home tenantId. */
@property (readonly, nullable) NSString *homeAccountId;

/*! Determines whether userId is displayable */
@property (readonly) BOOL userIdDisplayable;

/*! This property will be the userObjectId if it exists, or the subject if it does not. It is typically a GUID
    and not displayable. Using UniqueId as the ADUserIdentifierType will validate against this property. */
@property (readonly, nullable) NSString *uniqueId;

/*! May be null */
@property (readonly, nullable) NSString *givenName;

/*! May be null */
@property (readonly, nullable) NSString *familyName;

/*! May be null */
@property (readonly, nullable) NSString *identityProvider;

/*! May be null */
@property (readonly, nullable) NSString *eMail;

/*! May be null */
@property (readonly, nullable) NSString *uniqueName;

/*! May be null */
@property (readonly, nullable) NSString *upn;

/*! May be null */
@property (readonly, nullable) NSString *tenantId;

/*! May be null */
@property (readonly, nullable) NSString *subject;

/*! Unique object id that identifies the user. Internal user representation. May be null. " */
@property (readonly, nullable) NSString *userObjectId;

/*! Internal representation for guest users to the tenants. May be null. */
@property (readonly, nullable) NSString *guestId;

/*! The raw id_token claim string. */
@property (readonly, nonnull) NSString *rawIdToken;

/*! Contains all claims that had been read from the id_token. May be null, if the object was not created from a real id_token. */
@property (readonly, nullable) NSDictionary *allClaims;

/* A helper method to normalize userId, e.g. remove white spaces, lowercase. 
 Returns nil if userId is nil or empty. */
+ (nullable NSString *)normalizeUserId:(nonnull NSString *)userId;

@end

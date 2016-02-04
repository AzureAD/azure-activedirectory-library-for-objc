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
/*! Contains the details about a user that had authorized resource usage*/
@interface ADUserInformation : NSObject<NSCopying, NSSecureCoding>
{
    NSString* _userId;
    BOOL _userIdDisplayable;
    NSString* _uniqueId;
    NSString* _rawIdToken;
    NSDictionary* _allClaims;
}

/*! Factory method. The default initializer will throw unrecognized selector
 exception. Please use this one instead */
+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error;

/*! Factory method to extract user information from the AAD id_token parameter.
 @param: idToken: The contents of the id_token parameter, as passed by the server. */
+(ADUserInformation*) userInformationWithIdToken: (NSString*) idToken
                                           error: (ADAuthenticationError* __autoreleasing*) error;

/* This is the only unique property, as it is used in the key generation for the cache.
 Two ADUserInformation objects are considered the same if this property is the same. Using RequiredDisplayableId
 will validate against this property. */
@property (readonly) NSString* userId;

/*! Determines whether userId is displayable */
@property (readonly) BOOL userIdDisplayable;

/*! This property will be the userObjectId if it exists, or the subject if it does not. It is typically a GUID
    and not displayable. Using UniqueId as the ADUserIdentifierType will validate against this property. */
@property (readonly) NSString* uniqueId;

/*! May be null */
@property (readonly) NSString* givenName;

/*! May be null */
@property (readonly) NSString* familyName;

/*! May be null */
@property (readonly) NSString* identityProvider;

/*! May be null */
@property (readonly) NSString* eMail;

/*! May be null */
@property (readonly) NSString* uniqueName;

/*! May be null */
@property (readonly) NSString* upn;

/*! May be null */
@property (readonly) NSString* tenantId;

/*! May be null */
@property (readonly) NSString* subject;

/*! Unique object id that identifies the user. Internal user representation. May be null. " */
@property (readonly) NSString* userObjectId;

/*! Internal representation for guest users to the tenants. May be null. */
@property (readonly) NSString* guestId;

/*! The raw id_token claim string. */
@property (readonly) NSString* rawIdToken;

/*! Contains all claims that had been read from the id_token. May be null, if the object was not created from a real id_token. */
@property (readonly) NSDictionary* allClaims;

/* A helper method to normalize userId, e.g. remove white spaces, lowercase. 
 Returns nil if userId is nil or empty. */
+(NSString*) normalizeUserId: (NSString*) userId;

@end

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
@interface ADProfileInfo : NSObject<NSCopying, NSSecureCoding>

/*! Factory method. The default initializer will throw unrecognized selector
 exception. Please use this one instead */
+ (ADProfileInfo*)profileInfoWithUsername:(NSString*)username
                                    error:(ADAuthenticationError* __autoreleasing*)error;

/*! Factory method to extract user information from the AAD id_token parameter.
 @param: idToken: The contents of the id_token parameter, as passed by the server. */
+ (ADProfileInfo*)profileInfoWithEncodedString:(NSString*)encodedString
                                         error:(ADAuthenticationError* __autoreleasing*)error;

@property (readonly) NSString* username;

/*! May be null */
@property (readonly) NSString* subject;

@property (readonly) NSString* friendlyName;

@property (readonly) NSString* tenantId;

/*! The raw id_token claim string. */
@property (readonly) NSString* rawProfileInfo;

/*! Contains all claims that had been read from the id_token. May be null, if the object was not created from a real id_token. */
@property (readonly) NSDictionary* allClaims;

/* A helper method to normalize userId, e.g. remove white spaces, lowercase. 
 Returns nil if userId is nil or empty. */
+ (NSString*)normalizeUserId:(NSString*)userId;

@end

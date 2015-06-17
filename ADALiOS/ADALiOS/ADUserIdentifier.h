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

typedef enum ADUserIdentifierType
{
    /*!
     When a ADUserIdentifier of this type is passed in a token acquisition operation the operation
     is gauranteed to return a token issued for a user with the corresponding UserIdentifier or
     fail.
     */
    UniqueId,
    
    /*!
     When a ADUserIdentifier of this type is passed in a token acquisition operation, the operation
     restricts cache matches to the value provided and injects it as a hint in the authentication
     experience. However the end user could overwrite that value, resulting in a token issued to
     a different account than the one specified in the ADUserIdentifier in input.
     */
    OptionalDisplayableId,
    
    /*!
     When a ADUserIdentifier of this type is passed in a token acquisition operation, the operation
     is guaranteed to return a token issued for the user with corresponding DisplayableId (UPN or
     email) or fail
     */
    RequiredDisplayableId,
} ADUserIdentifierType;

@interface ADUserIdentifier : NSObject

@property (readonly, retain) NSString* userId;
@property (readonly) ADUserIdentifierType type;

/*!
    Creates a ADUserIdentifier with the provided userId and RequiredDisplayableId type.
    @param  userId  The userid
 */
+ (ADUserIdentifier*)identifierWithId:(NSString*)userId;

/*!
    Creates a ADUserIdentifier with the provided userId and type.
    @param  userId  The userid
    @param  type    The type that describes how ADAL should validate this User ID.
 */
+ (ADUserIdentifier*)identifierWithId:(NSString*)userId
                                 type:(ADUserIdentifierType)type;

+ (ADUserIdentifier*)identifierWithId:(NSString *)userId
                       typeFromString:(NSString*)type;

- (NSString*)typeAsString;

@end

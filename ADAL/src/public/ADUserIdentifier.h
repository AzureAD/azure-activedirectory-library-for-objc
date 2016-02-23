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

@class ADUserInformation;

@interface ADUserIdentifier : NSObject
{
    NSString* _userId;
    ADUserIdentifierType _type;
}

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

+ (BOOL)identifier:(ADUserIdentifier*)identifier
       matchesInfo:(ADUserInformation*)info;

- (NSString*)userIdMatchString:(ADUserInformation*)info;

- (NSString*)typeAsString;
+ (NSString*)stringForType:(ADUserIdentifierType)type;

- (BOOL)isDisplayable;

@end

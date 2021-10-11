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


#import "ADALUserIdentifier.h"
#import "ADALErrorCodes.h"
#import "ADALUserInformation.h"
#import "ADALHelpers.h"

#define DEFAULT_USER_TYPE RequiredDisplayableId

@implementation ADALUserIdentifier

@synthesize userId = _userId;
@synthesize type = _type;

+ (ADALUserIdentifier*)identifierWithId:(NSString*)userId
{
    ADALUserIdentifier* identifier = [[ADALUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [ADALHelpers normalizeUserId:userId];
    identifier->_type = DEFAULT_USER_TYPE;
    
    return identifier;
}

+ (ADALUserIdentifier*)identifierWithId:(NSString*)userId
                                 type:(ADALUserIdentifierType)type
{
    ADALUserIdentifier* identifier = [[ADALUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [ADALHelpers normalizeUserId:userId];
    identifier->_type = type;
    
    return identifier;
}

+ (ADALUserIdentifier*)identifierWithId:(NSString *)userId
                       typeFromString:(NSString*)type
{
    ADALUserIdentifier* identifier = [[ADALUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = [ADALHelpers normalizeUserId:userId];
    identifier->_type = [ADALUserIdentifier typeFromString:type];
    
    return identifier;
}

+ (BOOL)identifier:(ADALUserIdentifier*)identifier
       matchesInfo:(ADALUserInformation*)info
{
    if (!identifier)
    {
        return YES;
    }
    
    ADALUserIdentifierType type = [identifier type];
    if (type == OptionalDisplayableId)
    {
        return YES;
    }
    
    if (!info)
    {
        return NO;
    }
    
    NSString* matchString = [identifier userIdMatchString:info];
    if (!matchString || [matchString isEqualToString:identifier.userId])
    {
        return YES;
    }
    
    return NO;
}

- (id)copyWithZone:(NSZone*)zone
{
    ADALUserIdentifier* identifier = [[ADALUserIdentifier allocWithZone:zone] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_type = _type;
    identifier->_userId = [_userId copyWithZone:zone];
    
    return identifier;
}

- (NSString*)userIdMatchString:(ADALUserInformation*)info
{
    switch(_type)
    {
        case UniqueId: return info.uniqueId;
        case OptionalDisplayableId: return nil;
        case RequiredDisplayableId: return info.userId;
    }
    
    MSID_LOG_ERROR(nil, @"Unrecognized type on identifier match: %d", _type);
    
    return nil;
}

#define ENUM_TO_STRING_CASE(_val) case _val: return @#_val;

- (NSString*)typeAsString
{
    return [ADALUserIdentifier stringForType:_type];
}

+ (NSString*)stringForType:(ADALUserIdentifierType)type
{
    switch (type)
    {
        ENUM_TO_STRING_CASE(UniqueId);
        ENUM_TO_STRING_CASE(OptionalDisplayableId);
        ENUM_TO_STRING_CASE(RequiredDisplayableId);
    }
}

- (BOOL)isDisplayable
{
    return (_type == RequiredDisplayableId || _type == OptionalDisplayableId);
}

#define CHECK_TYPE(_type) if( [@#_type isEqualToString:type] ) { return _type; }
+ (ADALUserIdentifierType)typeFromString:(NSString*)type
{
    if (!type)
    {
        // If we don't get a type string then just return default
        return DEFAULT_USER_TYPE;
    }
    
    CHECK_TYPE(UniqueId);
    CHECK_TYPE(OptionalDisplayableId);
    CHECK_TYPE(RequiredDisplayableId);
    
    // If it didn't match against a known type return default, but log an error
    MSID_LOG_ERROR(nil, @"Did not recognize type \"%@\"", type);
    
    return DEFAULT_USER_TYPE;
}

@end

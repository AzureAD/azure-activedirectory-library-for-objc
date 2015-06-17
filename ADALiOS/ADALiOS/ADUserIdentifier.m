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


#import "ADUserIdentifier.h"
#import "ADLogger.h"
#import "ADErrorCodes.h"

#define DEFAULT_USER_TYPE RequiredDisplayableId

@implementation ADUserIdentifier
{
    NSString* _userId;
    ADUserIdentifierType _type;
}

@synthesize userId = _userId;
@synthesize type = _type;

+ (ADUserIdentifier*)identifierWithId:(NSString*)userId
{
    ADUserIdentifier* identifier = [[ADUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = userId;
    identifier->_type = DEFAULT_USER_TYPE;
    
    return identifier;
}

+ (ADUserIdentifier*)identifierWithId:(NSString*)userId
                                 type:(ADUserIdentifierType)type
{
    ADUserIdentifier* identifier = [[ADUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = userId;
    identifier->_type = type;
    
    return identifier;
}

+ (ADUserIdentifier*)identifierWithId:(NSString *)userId
                       typeFromString:(NSString*)type
{
    ADUserIdentifier* identifier = [[ADUserIdentifier alloc] init];
    if (!identifier)
    {
        return nil;
    }
    
    identifier->_userId = userId;
    identifier->_type = [ADUserIdentifier typeFromString:type];
    
    return identifier;
}

#define ENUM_TO_STRING_CASE(_val) case _val: return @#_val;

- (NSString*)typeAsString
{
    switch (_type)
    {
        ENUM_TO_STRING_CASE(UniqueId);
        ENUM_TO_STRING_CASE(OptionalDisplayableId);
        ENUM_TO_STRING_CASE(RequiredDisplayableId);
    }
}

#define CHECK_TYPE(_type) if( [@#_type isEqualToString:type] ) { return _type; }
+ (ADUserIdentifierType)typeFromString:(NSString*)type
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
    NSString* log = [NSString stringWithFormat:@"Did not recognize type \"%@\"", type];
    AD_LOG_ERROR(log, AD_ERROR_UNEXPECTED, nil);
    return DEFAULT_USER_TYPE;
}

@end

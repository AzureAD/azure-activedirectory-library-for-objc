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
    identifier->_type = RequiredDisplayableId;
    
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

#define ENUM_CASE(_val) case _val: return @#_val;

- (NSString*)typeAsString
{
    switch (_type)
    {
        ENUM_CASE(UniqueId);
        ENUM_CASE(OptionalDisplayableId);
        ENUM_CASE(RequiredDisplayableId);
    }
}

@end

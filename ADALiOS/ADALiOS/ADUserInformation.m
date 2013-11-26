// Created by Boris Vidolov on 10/15/13.
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

#import "ADUserInformation.h"
#import "ADALiOS.h"

@implementation ADUserInformation

-(id) init
{
    //Throws, as this init function should not be used
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id) initWithUserId: (NSString*) userId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(userId);//Shouldn't be called with nil.
    self = [super init];
    if (self)
    {
        //Minor canonicalization of the userId:
        _userId = [userId trimmedString].lowercaseString;
    }
    return self;
}

+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(userId);
    ADUserInformation* userInfo = [[ADUserInformation alloc] initWithUserId:userId];
    return userInfo;
}

-(id) copyWithZone:(NSZone*) zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    ADUserInformation* info = [[ADUserInformation allocWithZone:zone] initWithUserId:[self.userId copyWithZone:zone]];
    info.userIdDisplayable = self.userIdDisplayable;
    info.givenName = [self.givenName copyWithZone:zone];
    info.familyName = [self.familyName copyWithZone:zone];
    info.identityProvider = [self.identityProvider copyWithZone:zone];
    
    return info;
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

//Serialize:
-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.userId forKey:@"userId"];
    [aCoder encodeBool:self.userIdDisplayable forKey:@"userIdDisplayable"];
    [aCoder encodeObject:self.givenName forKey:@"givenName"];
    [aCoder encodeObject:self.familyName forKey:@"familyName"];
    [aCoder encodeObject:self.identityProvider forKey:@"identityProvider"];
}

//Deserialize:
-(id) initWithCoder:(NSCoder *) aDecoder
{
    NSString* storedUserId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"userId"];
    if ([NSString isStringNilOrBlank:storedUserId])
    {
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"Invalid userId: %@", storedUserId];
        AD_LOG_ERROR(@"Invalid user information", message, AD_ERROR_BAD_CACHE_FORMAT);
        
        return nil;
    }
    self = [self initWithUserId:storedUserId];
    if (self)
    {
        self.userIdDisplayable = [aDecoder decodeBoolForKey:@"userIdDisplayable"];
        self.givenName = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"givenName"];
        self.familyName = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"familyName"];
        self.identityProvider = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"identityProvider"];
    }
    
    return self;
}

@end

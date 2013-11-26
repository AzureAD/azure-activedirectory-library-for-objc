// Created by Boris Vidolov on 11/19/13.
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

#import "ADDefaultTokenCacheStorePersistance.h"

@implementation ADDefaultTokenCacheStorePersistance

-(id) initWithUpperVersion: (int16_t) _upperVersion
              lowerVersion: (int16_t) _lowerVersion
                cacheItems: (NSArray*) _cacheItems
{
    self = [super init];
    if (self)
    {
        upperVersion = _upperVersion;
        lowerVersion = _lowerVersion;
        cacheItems = _cacheItems;
    }
    return self;
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeInt32:upperVersion forKey:@"upperVersion"];
    [aCoder encodeInt32:lowerVersion forKey:@"lowerVersion"];
    [aCoder encodeObject:cacheItems forKey:@"cacheItems"];
}

-(id) initWithCoder:(NSCoder *)aDecoder
{
    self = [super self];
    if (self)
    {
        upperVersion = [aDecoder decodeInt32ForKey:@"upperVersion"];
        lowerVersion = [aDecoder decodeInt32ForKey:@"lowerVersion"];
        cacheItems = [aDecoder decodeObjectOfClass:[NSArray class] forKey:@"cacheItems"];
    }
    return self;
}

@end

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
#import "ADLogger.h"

const int16_t UPPER_VERSION = 1;
const int16_t LOWER_VERSION = 0;

@implementation ADDefaultTokenCacheStorePersistance

-(id) initWithCacheItems: (NSArray*) _cacheItems
{
    self = [super init];
    if (self)
    {
        upperVersion = UPPER_VERSION;
        lowerVersion = LOWER_VERSION;
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
        
        if (upperVersion > UPPER_VERSION)
        {
            //A new, incompatible version of the cache is stored, ignore the cache:
            AD_LOG_ERROR_F(@"Future file format", AD_ERROR_CACHE_PERSISTENCE,
                           @"The version (%d.%d) of the cache file is not supported.",
                           upperVersion, lowerVersion)
            return nil;
        }
        
        //The future deserialization logic may have different versions read:
        cacheItems = [aDecoder decodeObjectOfClass:[NSArray class] forKey:@"cacheItems"];
    }
    return self;
}

@end

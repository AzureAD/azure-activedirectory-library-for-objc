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

const int16_t UPPER_VERSION = 1;
const int16_t LOWER_VERSION = 0;

@implementation ADDefaultTokenCacheStorePersistance

-(id) initWithCacheItems:(NSArray*)cacheItems
{
    self = [super init];
    if (self)
    {
        _upperVersion = UPPER_VERSION;
        _lowerVersion = LOWER_VERSION;
        _cacheItems   = SAFE_ARC_RETAIN(cacheItems);
    }
    return self;
}

- (void)dealloc
{
    AD_LOG_VERBOSE(@"ADDefaultTokenCacheStorePersistance", @"dealloc");
    
    SAFE_ARC_RELEASE(_cacheItems);
    
    SAFE_ARC_SUPER_DEALLOC();
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeInt32:_upperVersion forKey:@"upperVersion"];
    [aCoder encodeInt32:_lowerVersion forKey:@"lowerVersion"];
    [aCoder encodeObject:_cacheItems forKey:@"cacheItems"];
}

-(id) initWithCoder:(NSCoder *)aDecoder
{
    self = [super self];
    if (self)
    {
        _upperVersion = [aDecoder decodeInt32ForKey:@"upperVersion"];
        _lowerVersion = [aDecoder decodeInt32ForKey:@"lowerVersion"];
        
        if (_upperVersion > UPPER_VERSION)
        {
            //A new, incompatible version of the cache is stored, ignore the cache:
            AD_LOG_ERROR_F(@"Future file format", AD_ERROR_CACHE_PERSISTENCE,
                           @"The version (%d.%d) of the cache file is not supported.",
                           _upperVersion, _lowerVersion);
            return nil;
        }
        
        //The future deserialization logic may have different versions read:
        _cacheItems = [aDecoder decodeObjectOfClass:[NSArray class] forKey:@"cacheItems"];
        SAFE_ARC_RETAIN(_cacheItems);
    }
    return self;
}

@end

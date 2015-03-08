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


#import "ADBrokerPRTCacheItem.h"

@implementation ADBrokerPRTCacheItem

//Multi-resource refresh tokens are stored separately, as they apply to all resources. As such,
//we create a special, "broad" cache item, with nil resource and access token:
-(BOOL) isMultiResourceRefreshToken
{
    return NO;
}

-(id) copyWithZone:(NSZone*) zone
{
    ADBrokerPRTCacheItem* item = [super copyWithZone:zone];
    item.tokenType = [self.tokenType copyWithZone:zone];
    item.primaryRefreshToken = [self.primaryRefreshToken copyWithZone:zone];
    item.sessionKey = [self.sessionKey copyWithZone:zone];
    return item;
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

//Serializer:
-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [super encodeWithCoder:aCoder];
    [aCoder encodeObject:self.tokenType forKey:@"tokenType"];
    [aCoder encodeObject:self.sessionKey forKey:@"sessionKey"];
}

//Deserializer:
-(id) initWithCoder:(NSCoder *)aDecoder
{
    self = [super initWithCoder:aDecoder];
    if (self)
    {
        self.tokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"tokenType"];
        self.primaryRefreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"primaryRefreshToken"];
        self.sessionKey = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"sessionKey"];
    }
    return self;
}

@end

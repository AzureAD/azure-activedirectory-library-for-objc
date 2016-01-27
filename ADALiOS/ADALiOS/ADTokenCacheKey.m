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


#import "ADALiOS.h"
#import "ADAuthenticationContext.h"
#import "ADInstanceDiscovery.h"
#import "ADTokenCacheKey.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheKey
{
    NSUInteger _hash;
}

- (id)init
{
    //Use the custom init instead. This one will throw.
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithAuthority:(NSString *)authority
               resource:(NSString *)resource
               clientId:(NSString *)clientId
{
    self = [super init];
    if (self)
    {
        //As the object is immutable we precalculate the hash:
        _hash = [[NSString stringWithFormat:@"##%@##%@##%@##", authority, resource, clientId]
                    hash];
        _authority = authority;
        _resource = resource;
        _clientId = clientId;
    }
    
    return self;
}

+ (id)keyWithAuthority:(NSString *)authority
              resource:(NSString *)resource
              clientId:(NSString *)clientId
                 error:(ADAuthenticationError * __autoreleasing *)error
{
    API_ENTRY;
    //Trimm first for faster nil or empty checks. Also lowercase and trimming is
    //needed to ensure that the cache handles correctly same items with different
    //character case:
    authority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    resource = resource.adTrimmedString.lowercaseString;
    clientId = clientId.adTrimmedString.lowercaseString;
    RETURN_NIL_ON_NIL_ARGUMENT(authority);//Canonicalization will return nil on empty or bad URL.
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(clientId);
    
    ADTokenCacheKey* key = [ADTokenCacheKey alloc];
    return [key initWithAuthority:authority resource:resource clientId:clientId];
}

- (NSUInteger)hash
{
    return _hash;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
    {
        return NO;
    }
    
    if (![object isKindOfClass:[ADTokenCacheKey class]])
    {
        return NO;
    }
    
    ADTokenCacheKey* key = object;
    
    //First check the fields which cannot be nil:
    if (![self.authority isEqualToString:key.authority] ||
        ![self.clientId isEqualToString:key.clientId])
    {
        return NO;
    }
    
    //Now handle the case of nil resource:
    if (!self.resource)
    {
        return !key.resource;//Both should be nil to be equal
    }
    else
    {
        return [self.resource isEqualToString:key.resource];
    }
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.authority forKey:@"authority"];
    [aCoder encodeObject:self.resource forKey:@"resource"];
    [aCoder encodeObject:self.clientId forKey:@"clientId"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
    _resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    
    return self;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (id)copyWithZone:(NSZone *) zone
{
    return [[self.class allocWithZone:zone] initWithAuthority:[self.authority copyWithZone:zone]
                                                     resource:[self.resource copyWithZone:zone]
                                                     clientId:[self.clientId copyWithZone:zone]];
}

@end

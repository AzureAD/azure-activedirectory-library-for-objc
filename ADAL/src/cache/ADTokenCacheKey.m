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


#import "ADAL_Internal.h"
#import "ADAuthenticationContext.h"
#import "ADInstanceDiscovery.h"
#import "ADTokenCacheKey.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheKey

@synthesize authority = _authority;
@synthesize resource = _resource;
@synthesize clientId = _clientId;

- (void)calculateHash
{
    _hash = [[NSString stringWithFormat:@"##%@##%@##%@##", _authority, _resource, _clientId]
             hash];
}

- (id)initWithAuthority:(NSString *)authority
               resource:(NSString *)resource
               clientId:(NSString *)clientId
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = authority;
    SAFE_ARC_RETAIN(_authority);
    _resource = resource;
    SAFE_ARC_RETAIN(_resource);
    _clientId = clientId;
    SAFE_ARC_RETAIN(_clientId);
    
    [self calculateHash];
    
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
    RETURN_NIL_ON_NIL_ARGUMENT(authority);
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(clientId);
    
    ADTokenCacheKey* key = [[ADTokenCacheKey alloc] initWithAuthority:authority resource:resource clientId:clientId];
    SAFE_ARC_AUTORELEASE(key);
    return key;
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
    SAFE_ARC_RETAIN(_authority);
    _resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
    SAFE_ARC_RETAIN(_resource);
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    SAFE_ARC_RETAIN(_clientId);
    
    [self calculateHash];
    
    return self;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (id)copyWithZone:(NSZone *) zone
{
    ADTokenCacheKey* key = [[ADTokenCacheKey allocWithZone:zone] init];
    
    key->_authority = [_authority copyWithZone:zone];
    key->_clientId = [_clientId copyWithZone:zone];
    key->_resource = [_resource copyWithZone:zone];
    
    [key calculateHash];
    
    return key;
}

@end

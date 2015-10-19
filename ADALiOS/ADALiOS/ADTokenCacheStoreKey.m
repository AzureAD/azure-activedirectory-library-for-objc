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
#import "ADTokenCacheStoreKey.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheStoreKey

- (id)init
{
    //Use the custom init instead. This one will throw.
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithAuthority:(NSString*)authority
               clientId:(NSString*)clientId
                 userId:(NSString*)userId
               uniqueId:(NSString*)uniqueId
                 idType:(ADUserIdentifierType)idType
                 policy:(NSString*)policy
                 scopes:(NSSet*)scopes
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    //As the object is immutable we precalculate the hash:
    _key = [[NSString alloc] initWithFormat:@"%@##%@", authority, clientId];
    _hash = [_key hash];
    _authority = authority;
    _clientId = clientId;
    _userId = userId;
    _uniqueId = uniqueId;
    _identifierType = idType;
    _policy = policy;
    _scopes = scopes;
    
    return self;
}

+ (ADTokenCacheStoreKey*)keyWithAuthority:(NSString*)authority
                                 clientId:(NSString*)clientId
                                   userId:(NSString*)userId
                                 uniqueId:(NSString*)uniqueId
                                   idType:(ADUserIdentifierType)idType
                                   policy:(NSString*)policy
                                   scopes:(NSSet*)scopes
                                    error:(ADAuthenticationError* __autoreleasing*)error
{
    API_ENTRY;
    //Trimm first for faster nil or empty checks. Also lowercase and trimming is
    //needed to ensure that the cache handles correctly same items with different
    //character case:
    authority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    clientId = clientId.adTrimmedString.lowercaseString;
    RETURN_NIL_ON_NIL_ARGUMENT(authority);//Canonicalization will return nil on empty or bad URL.
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(clientId);
    
    return [[ADTokenCacheStoreKey alloc] initWithAuthority:authority
                                                  clientId:clientId
                                                    userId:userId
                                                  uniqueId:uniqueId
                                                    idType:idType
                                                    policy:policy
                                                    scopes:scopes];
}

- (NSUInteger)hash
{
    return _hash;
}

- (BOOL)isEqual:(id)object
{
    ADTokenCacheStoreKey* key = object;
    if (!key)
        return NO;
    
    if (_hash != key->_hash)
        return NO;
    
    //First check the fields which cannot be nil:
    if (![_authority isEqualToString:key->_authority] ||
        ![_clientId isEqualToString:key->_clientId])
        return NO;
    
    return YES;
}

- (id)copyWithZone:(NSZone*) zone
{
    return [[self.class allocWithZone:zone] initWithAuthority:[self.authority copyWithZone:zone]
                                                     clientId:[self.clientId copyWithZone:zone]
                                                       userId:[self.userId copyWithZone:zone]
                                                     uniqueId:[self.uniqueId copyWithZone:zone]
                                                       idType:self.identifierType
                                                       policy:self.policy
                                                       scopes:[self.scopes copyWithZone:zone]];
}

- (NSString*)userCacheKey
{
    switch (_identifierType)
    {
        case OptionalDisplayableId:
        case RequiredDisplayableId:
            return _userId;
            
        case UniqueId:
            return _uniqueId;
    }
    
    AD_LOG_ERROR_F(@"Unkonwn user identifier type in ADTokenCacheStoreKey", AD_ERROR_CACHE_PERSISTENCE, @"erorr: %d", (int)_identifierType);
    return nil;
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"{ ADTokenCacheStoreKey authority=%@ clientId=%@ userId=%@ uniqueId=%@ idType=%@ scopes=%@ }",
            _authority, _clientId, _userId, _uniqueId, [ADUserIdentifier stringForType:_identifierType], _scopes];
}

@end

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

#import "IPAuthorization.h"

@interface IPAuthorization ()
@end

@implementation IPAuthorization

+ (NSString *)cacheKeyForServer:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope
{
    if ( !authorizationServer || authorizationServer.length == 0 )
        return nil;
    
    if ( !resource || resource.length == 0 )
        return nil;
    
    return [NSString stringWithFormat:@"%@:%@:%@", [self normalizeAuthorizationServer:authorizationServer], resource, ( scope ) ? scope : @""];
}

+ (NSString *)normalizeAuthorizationServer:(NSString *)authorizationServer
{
    if ( authorizationServer == nil || authorizationServer.length == 0 )
        return nil;
    
    // Final step is trimming any trailing /, /authorize or /token from the URL
    // to get to the base URL for the authorization server. After that, we
    // append either /authorize or /token dependent on the request that
    // is being made to the server.
    //
    // TODO: These compares must be changed to case-insensitive
    NSRange substringRange = {0, 0 };
    
    if ( [authorizationServer hasSuffix:@"/authorize" ] )
    {
        substringRange.location = 0;
        substringRange.length   = authorizationServer.length - @"/authorize".length;
        
        return [authorizationServer substringWithRange:substringRange];
    }
    else if ( [authorizationServer hasSuffix:@"/token" ] )
    {
        substringRange.location = 0;
        substringRange.length   = authorizationServer.length - @"/token".length;
        
        return [authorizationServer substringWithRange:substringRange];
    }
    else if ( [authorizationServer hasSuffix:@"/" ] )
    {
        substringRange.location = 0;
        substringRange.length   = authorizationServer.length - @"/".length;
        
        return [authorizationServer substringWithRange:substringRange];
    }
    else
    {
        return authorizationServer;
    }
}

- (id)init
{
    NSAssert( false, @"Direct initialization not allowed" );
    
    return nil;
}

- (id)initWithServer:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope
{
    if ( authorizationServer == nil || authorizationServer.length == 0 )
        return nil;

    if ( resource == nil || resource.length == 0 )
        return nil;
    
    if ( ( self = [super init] ) != nil )
    {
        _authorizationServer = [self.class normalizeAuthorizationServer:authorizationServer];
        _resource            = resource;
        _scope               = scope;
        _cacheKey            = [self.class cacheKeyForServer:_authorizationServer resource:resource scope:scope];
        
        _accessToken     = nil;
        _accessTokenType = nil;
        _code            = nil;
        _expires         = [NSDate distantFuture];
        _refreshToken    = nil;
    }
    
    return self;
}

- (BOOL)isExpired
{
    if ( [_expires compare:[NSDate dateWithTimeIntervalSinceNow:300.0]] == NSOrderedAscending )
        return YES;
    
    return NO;
}

- (BOOL)isRefreshable
{
    return _refreshToken != nil;
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:_accessToken forKey:@"accessToken"];
    [aCoder encodeObject:_accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:_authorizationServer forKey:@"authorizationServer"];
    [aCoder encodeObject:_cacheKey forKey:@"cacheKey"];
    [aCoder encodeObject:_expires forKey:@"expires"];
    [aCoder encodeObject:_refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:_resource forKey:@"resource"];
    [aCoder encodeObject:_scope forKey:@"scope"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if ( ( self = [super init] ) != nil )
    {
        _accessToken         = (NSString *)[aDecoder decodeObjectForKey:@"accessToken"];
        _accessTokenType     = (NSString *)[aDecoder decodeObjectForKey:@"accessTokenType"];
        _authorizationServer = (NSString *)[aDecoder decodeObjectForKey:@"authorizationServer"];
        _cacheKey            = (NSString *)[aDecoder decodeObjectForKey:@"cacheKey"];
        _expires             = (NSDate *)[aDecoder decodeObjectForKey:@"expires"];
        _refreshToken        = (NSString *)[aDecoder decodeObjectForKey:@"refreshToken"];
        _resource            = (NSString *)[aDecoder decodeObjectForKey:@"resource"];
        _scope               = (NSString *)[aDecoder decodeObjectForKey:@"scope"];
    }

    return self;
}

@end

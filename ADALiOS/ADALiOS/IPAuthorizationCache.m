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
#import "IPAuthorizationCache.h"

@implementation IPAuthorizationMemoryCache
{
    NSMutableDictionary *_cache;
    NSLock              *_cacheLock;
}

#pragma mark - Instance Management

// The singleton instance of IPAuthenticationSettings
+ (IPAuthorizationMemoryCache *)sharedInstance
{
    static IPAuthorizationMemoryCache *object = nil;
    static dispatch_once_t       predicate;
    
    dispatch_once( &predicate,
                  ^{
                      object = [[[self class] allocPrivate] init];
                  });
    
    return object;
}

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)init
{
    if ( ( self = [super init] ) != nil )
    {
        _cache     = [[NSMutableDictionary alloc] initWithCapacity:6];
        _cacheLock = [[NSLock alloc] init];
    }
    
    return self;
}

#pragma mark - IPAuthenticationCache Protocol

- (IPAuthorization *)authorizationForKey:(NSString *)key
{
    [_cacheLock lock];
    IPAuthorization *authorization = [_cache objectForKey:key];
    [_cacheLock unlock];
    
    if ( authorization )
    {
        NSAssert( [key isEqualToString:authorization.cacheKey], @"Cache Key Inconsistency" );
    }
    
    return authorization;
}

- (void)setAuthorization:(IPAuthorization *)authorization forKey:(NSString *)key
{
    if ( !authorization || !key || key.length == 0 )
        return;
    
    NSAssert( [key isEqualToString:authorization.cacheKey], @"Cache Key Inconsistency" );
    
    [_cacheLock lock];
    [_cache setObject:authorization forKey:key];
    [_cacheLock unlock];
}

- (void)removeAuthorizationForKey:(NSString *)key
{
    [_cacheLock lock];
    [_cache removeObjectForKey:key];
    [_cacheLock unlock];
}

- (void)removeAllAuthorizations
{
    [_cacheLock lock];
    [_cache removeAllObjects];
    [_cacheLock unlock];
}

@end

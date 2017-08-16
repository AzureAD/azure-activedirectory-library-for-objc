// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADAadAuthorityCache.h"

#import "NSURL+ADExtensions.h"

#include <pthread.h>

@implementation ADAadAuthorityCacheRecord

@end

@implementation ADAadAuthorityCache

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    
    _map = [NSMutableDictionary new];
    pthread_rwlock_init(&_rwLock, NULL);
    
    return self;
}

- (void)dealloc
{
    pthread_rwlock_destroy(&_rwLock);
}

- (void)processMetadata:(NSArray<NSDictionary *> *)metadata
              authority:(NSURL *)authority
{
    [self getWriteLock];
    
    for (NSDictionary *environment in metadata)
    {
        __auto_type *record = [ADAadAuthorityCacheRecord new];
        record.validated = YES;
        record.networkHost = environment[@"preferred_network"];
        record.cacheHost = environment[@"preferred_cache"];
        
        NSArray *aliases = environment[@"aliases"];
        record.aliases = aliases;
        
        for (NSString *alias in aliases)
        {
            _map[alias] = record;
        }
    }
    
    // In case the authority we were looking for wasn't in the metadata
    NSString *authorityHost = authority.adHostWithPortIfNecessary;
    if (!_map[authorityHost])
    {
        __auto_type *record = [ADAadAuthorityCacheRecord new];
        record.validated = YES;
        record.cacheHost = authorityHost;
        record.networkHost = authorityHost;
        
        _map[authority.adHostWithPortIfNecessary] = record;
    }
    pthread_rwlock_unlock(&_rwLock);
}

- (void)addInvalidRecord:(NSURL *)authority
              oauthError:(ADAuthenticationError *)oauthError
{
    [self getWriteLock];
    __auto_type *record = [ADAadAuthorityCacheRecord new];
    record.validated = NO;
    record.error = oauthError;
    _map[authority.adHostWithPortIfNecessary] = record;
    pthread_rwlock_unlock(&_rwLock);
}

#pragma mark -
#pragma mark Cache Accessors

- (ADAadAuthorityCacheRecord *)checkCacheImpl:(NSURL *)authority
{
    __auto_type record = _map[authority.adHostWithPortIfNecessary];
    pthread_rwlock_unlock(&_rwLock);
    
    return record;
}

- (ADAadAuthorityCacheRecord *)tryCheckCache:(NSURL *)authority
{
    if (pthread_rwlock_tryrdlock(&_rwLock) == 0)
    {
        return [self checkCacheImpl:authority];
    }
    
    return nil;
}

- (ADAadAuthorityCacheRecord *)checkCache:(NSURL *)authority
{
    int status = pthread_rwlock_rdlock(&_rwLock);
    // This should be an extremely rare condition, and typically only happens if something
    // (a memory stomper bug) stomps on the rw lock. In that case we're in a really bad state anyways
    // and should expect to fail soon.
    if (status != 0)
    {
        @throw [NSException exceptionWithName:@"ADALException"
                                       reason:[NSString stringWithFormat:@"Unable to get lock, error code %d", status]
                                     userInfo:nil];
    }
    
    return [self checkCacheImpl:authority];
}


- (BOOL)getWriteLock
{
    int status = pthread_rwlock_wrlock(&_rwLock);
    if (status != 0)
    {
        @throw [NSException exceptionWithName:@"ADALException"
                                       reason:[NSString stringWithFormat:@"Unable to get lock, error code %d", status]
                                     userInfo:nil];
    }
    
    return YES;
}

static NSURL *urlForPreferredHost(NSURL *url, NSString *preferredHost)
{
    if (!preferredHost)
    {
        return url;
    }
    
    // If the host is already (functionally) the same then just return the passed in URL.
    if ([url.host isEqualToString:preferredHost] ||
        [url.adHostWithPortIfNecessary isEqualToString:preferredHost])
    {
        return url;
    }
    
    // Otherwise switch the host for the preferred one.
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    
    // I hope there's never a case where there's percent encoded characters in the host, but using
    // this setter prevents NSURLComponents from trying to do any further mangling on the string,
    // probably a good thing.
    components.percentEncodedHost = preferredHost;
    
    return components.URL;
}

- (NSURL *)networkUrlForAuthority:(NSURL *)authority
{
    __auto_type record = [self checkCache:authority];
    if (!record)
    {
        return nil;
    }
    
    return urlForPreferredHost(authority, record.networkHost);
}

- (NSURL *)cacheUrlForAuthority:(NSURL *)authority
{
    __auto_type record = [self checkCache:authority];
    if (!record)
    {
        return nil;
    }
    
    return urlForPreferredHost(authority, record.cacheHost);
}

@end

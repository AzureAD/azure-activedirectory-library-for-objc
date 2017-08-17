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

#define CHECK_CLASS_TYPE(_CHK, _CLS, _ERROR) \
    if (![_CHK isKindOfClass:[_CLS class]]) { \
        ADAuthenticationError *adError = \
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_INVALID_RESPONSE \
                                       protocolCode:nil \
                                       errorDetails:_ERROR \
                                      correlationId:context.correlationId]; \
        if (error) { *error = adError; } \
        return NO; \
    }

@implementation ADAadAuthorityCacheRecord

@end

@implementation ADAadAuthorityCache

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    
    _recordMap = [NSMutableDictionary new];
    pthread_rwlock_init(&_rwLock, NULL);
    
    return self;
}

- (void)dealloc
{
    pthread_rwlock_destroy(&_rwLock);
}

- (BOOL)processMetadata:(NSArray<NSDictionary *> *)metadata
              authority:(NSURL *)authority
                context:(id<ADRequestContext>)context
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    if (metadata != nil)
    {
        CHECK_CLASS_TYPE(metadata, NSArray, @"JSON metadata from authority validation is not an array");
    }
    
    [self getWriteLock];
    BOOL ret = [self processImpl:metadata authority:authority context:context error:error];
    pthread_rwlock_unlock(&_rwLock);
    
    return ret;
}

- (BOOL)processImpl:(NSArray<NSDictionary *> *)metadata
          authority:(NSURL *)authority
            context:(id<ADRequestContext>)context
              error:(ADAuthenticationError * __autoreleasing *)error
{
    if (metadata.count == 0)
    {
        AD_LOG_INFO(@"No metadata returned from authority validation", context.correlationId, nil);
    }
    else
    {
        AD_LOG_INFO(@"Caching AAD Environements:", context.correlationId, nil);
    }
    
    NSMutableArray<ADAadAuthorityCacheRecord *> *recordsToAdd = [NSMutableArray new];
    
    for (NSDictionary *environment in metadata)
    {
        CHECK_CLASS_TYPE(environment, NSDictionary, @"JSON metadata entry is not a dictionary");
        
        __auto_type *record = [ADAadAuthorityCacheRecord new];
        record.validated = YES;
        
        NSString *networkHost = environment[@"preferred_network"];
        CHECK_CLASS_TYPE(networkHost, NSString, @"\"preferred_network\" in JSON authority validation metadata must be a string");
        record.networkHost = networkHost;
        
        NSString *cacheHost = environment[@"preferred_cache"];
        CHECK_CLASS_TYPE(cacheHost, NSString, @"\"preferred_cache\" in JSON authority validation metadata must be a string");
        record.cacheHost = cacheHost;
        
        NSArray *aliases = environment[@"aliases"];
        CHECK_CLASS_TYPE(aliases, NSArray, @"\"alias\" in JSON authority validation metadata must be an array");
        record.aliases = aliases;
        
        for (NSString *alias in aliases)
        {
            CHECK_CLASS_TYPE(alias, NSString, @"\"alias\" in JSON authority validation metadata must be an array of strings");
        }
        
        [recordsToAdd addObject:record];
    }
    
    for (ADAadAuthorityCacheRecord *record in recordsToAdd)
    {
        __auto_type aliases = record.aliases;
        for (NSString *alias in aliases)
        {
            _recordMap[alias] = record;
        }
        
        AD_LOG_INFO(([NSString stringWithFormat:@"(%@, %@) : %@", record.networkHost, record.cacheHost, aliases]), context.correlationId, nil);
    }
    
    // In case the authority we were looking for wasn't in the metadata
    NSString *authorityHost = authority.adHostWithPortIfNecessary;
    if (!_recordMap[authorityHost])
    {
        __auto_type *record = [ADAadAuthorityCacheRecord new];
        record.validated = YES;
        record.cacheHost = authorityHost;
        record.networkHost = authorityHost;
        
        _recordMap[authorityHost] = record;
    }
    
    return YES;
}

- (void)addInvalidRecord:(NSURL *)authority
              oauthError:(ADAuthenticationError *)oauthError
                 context:(id<ADRequestContext>)context
{
    [self getWriteLock];
    AD_LOG_WARN(@"Caching Invalid AAD Instance", context.correlationId, nil);
    __auto_type *record = [ADAadAuthorityCacheRecord new];
    record.validated = NO;
    record.error = oauthError;
    _recordMap[authority.adHostWithPortIfNecessary] = record;
    pthread_rwlock_unlock(&_rwLock);
}

#pragma mark -
#pragma mark Cache Accessors

- (ADAadAuthorityCacheRecord *)checkCacheImpl:(NSURL *)authority
{
    __auto_type record = _recordMap[authority.adHostWithPortIfNecessary];
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
        AD_LOG_ERROR(@"Failed to grab authority cache read lock.", status, nil, nil);
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
        AD_LOG_ERROR(@"Failed to grab authority cache write lock.", status, nil, nil);
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
    
    if ([url.adHostWithPortIfNecessary isEqualToString:preferredHost])
    {
        return url;
    }
    
    // Otherwise switch the host for the preferred one.
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    
    NSArray *hostComponents = [preferredHost componentsSeparatedByString:@":"];
    
    // I hope there's never a case where there's percent encoded characters in the host, but using
    // this setter prevents NSURLComponents from trying to do any further mangling on the string,
    // probably a good thing.
    components.percentEncodedHost = hostComponents[0];
    
    if (hostComponents.count > 1)
    {
        components.port = [NSNumber numberWithInt:[hostComponents[1] intValue]];
    }
    else
    {
        components.port = nil;
    }
    
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

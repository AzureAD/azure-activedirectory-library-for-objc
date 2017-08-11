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


#import "ADAuthorityValidation.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADAuthorityValidationRequest.h"
#import "ADHelpers.h"
#import "ADOAuth2Constants.h"
#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"
#import "NSURL+ADExtensions.h"

#include <pthread.h>


// Trusted relation for webFinger
static NSString* const s_kTrustedRelation              = @"http://schemas.microsoft.com/rel/trusted-realm";

// Trusted authorities
static NSString* const s_kTrustedAuthority             = @"login.windows.net";
static NSString* const s_kTrustedAuthorityUS           = @"login.microsoftonline.us";
static NSString* const s_kTrustedAuthorityChina        = @"login.chinacloudapi.cn";
static NSString* const s_kTrustedAuthorityGermany      = @"login.microsoftonline.de";
static NSString* const s_kTrustedAuthorityWorldWide    = @"login.microsoftonline.com";
static NSString* const s_kTrustedAuthorityUSGovernment = @"login-us.microsoftonline.com";

// AAD validation check constant
static NSString* const s_kTenantDiscoveryEndpoint      = @"tenant_discovery_endpoint";

// DRS server error message constant
static NSString* const s_kDrsDiscoveryError            = @"DRS discovery was invalid or failed to return PassiveAuthEndpoint";
static NSString* const s_kWebFingerError               = @"WebFinger request was invalid or failed";

@interface ADAuthorityValidationAADRecord : NSObject

@property BOOL validated;
@property ADAuthenticationError *error;

@property NSString *networkHost;
@property NSString *cacheHost;
@property NSArray<NSString *> *aliases;

@end

@implementation ADAuthorityValidationAADRecord

@end

@implementation ADAuthorityValidation
{
    NSMutableDictionary *_validatedAdfsAuthorities;
    NSMutableDictionary<NSString *, ADAuthorityValidationAADRecord *> *_validatedAADAuthorities;
    NSSet *_whitelistedAADHosts;
    
    pthread_rwlock_t _rwLock;
    dispatch_queue_t _aadValidationQueue;
}


+ (ADAuthorityValidation *)sharedInstance
{
    static ADAuthorityValidation *singleton = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        singleton = [[ADAuthorityValidation alloc] init];
    });
    
    return singleton;
}

- (id)init
{
    self = [super init];
    if (!self)
    {
        return nil;
    }
    
    _validatedAdfsAuthorities = [NSMutableDictionary new];
    _validatedAADAuthorities = [NSMutableDictionary new];
    
    pthread_rwlock_init(&_rwLock, NULL);
    
    _whitelistedAADHosts = [NSSet setWithObjects:s_kTrustedAuthority, s_kTrustedAuthorityUS,
                            s_kTrustedAuthorityChina, s_kTrustedAuthorityGermany,
                            s_kTrustedAuthorityWorldWide, s_kTrustedAuthorityUSGovernment, nil];
    
    // A serial dispatch queue for all authority validation operations. A very common pattern is for
    // applications to spawn a bunch of threads and call acquireToken on them right at the start. Many
    // of those acquireToken calls will be to the same authority. To avoid making the exact same
    // authority validation network call multiple times we throw the requests in this validation
    // queue.
    _aadValidationQueue = dispatch_queue_create("adal.validation.queue", DISPATCH_QUEUE_SERIAL);
    
    return self;
}


#pragma mark - caching
- (BOOL)addValidAuthority:(NSURL *)authority domain:(NSString *)domain
{
    if (!domain || !authority)
    {
        return NO;
    }
    
    // Get authorities for domain (UPN suffix) and create one if needed
    NSMutableSet *authorities = [_validatedAdfsAuthorities objectForKey:domain];
    if (!authorities)
    {
        authorities = [NSMutableSet new];
        [_validatedAdfsAuthorities setObject:authorities forKey:domain];
    }
  
    // Add given authority to trusted set for the domain
    [authorities addObject:authority];
    return YES;
}

- (BOOL)isAuthorityValidated:(NSURL *)authority domain:(NSString *)domain
{
    // Check for authority
    NSSet *authorities = [_validatedAdfsAuthorities objectForKey:domain];
    for (NSURL *url in authorities)
    {
        if([url isEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

// Checks the cache for previously validated authority.
// Note that the authority host should be normalized: no ending "/" and lowercase.
- (BOOL)isAuthorityValidated:(NSURL *)authority
{
    if (!authority)
    {
        return NO;
    }
    return _validatedAADAuthorities[authority.adHostWithPortIfNecessary].validated;
}


#pragma mark - Authority validation

- (void)validateAuthority:(ADRequestParameters*)requestParams
          completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    NSString *upn = requestParams.identifier.userId;
    NSString *authority = requestParams.authority;
    
    ADAuthenticationError *error = [ADHelpers checkAuthority:authority correlationId:requestParams.correlationId];
    if (error)
    {
        completionBlock(NO, error);
        return;
    }
    
    NSURL *authorityURL = [NSURL URLWithString:authority.lowercaseString];
    if (!authorityURL)
    {
        error = [ADAuthenticationError errorFromArgument:authority
                                            argumentName:@"authority"
                                           correlationId:requestParams.correlationId];
        completionBlock(NO, error);
        return;
    }
    
    // Check for AAD or ADFS
    if ([ADHelpers isADFSInstanceURL:authorityURL])
    {
        // Check for upn suffix
        NSString *upnSuffix = [ADHelpers getUPNSuffix:upn];
        if ([NSString adIsStringNilOrBlank:upnSuffix])
        {
            error = [ADAuthenticationError errorFromArgument:upnSuffix
                                                argumentName:@"user principal name"
                                               correlationId:requestParams.correlationId];
            completionBlock(NO, error);
            return;
        }
        
        // Validate ADFS authority
        [self validateADFSAuthority:authorityURL domain:upnSuffix requestParams:requestParams completionBlock:completionBlock];
    }
    else
    {
        // Validate AAD authority
        [self validateAADAuthority:authorityURL requestParams:requestParams completionBlock:completionBlock];
    }
}

- (NSURL *)networkUrlForAuthority:(NSURL *)authority
{
    return authority;
}

- (NSURL *)cacheUrlForAuthority:(NSURL *)authority
{
    return authority;
}


#pragma mark - AAD authority validation

- (BOOL)checkCacheImpl:(NSURL *)authority
       completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    __auto_type record = _validatedAADAuthorities[authority.adHostWithPortIfNecessary];
    pthread_rwlock_unlock(&_rwLock);
    
    if (record)
    {
        completionBlock(record.validated, record.error);
        return YES;
    }
    
    return NO;
}

- (BOOL)tryCheckCache:(NSURL *)authority
      completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    if (pthread_rwlock_tryrdlock(&_rwLock) == 0)
    {
        return [self checkCacheImpl:authority completionBlock:completionBlock];
    }
    
    return NO;
}

- (BOOL)checkCache:(NSURL *)authority
           context:(id<ADRequestContext>)context
   completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    int status = pthread_rwlock_rdlock(&_rwLock);
    // This should be an extremely rare condition, and typically only happens if something
    // (a memory stomper bug) stomps on the rw lock.
    if (status != 0)
    {
        // Because we're on a serialized queue here to ensure that we don't have more then one
        // validation network request at a time, we want to jump off this queue as quick as
        // possible whenever we hit an error to unblock the queue
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            ADAuthenticationError *error =
            [ADAuthenticationError errorWithDomain:NSOSStatusErrorDomain
                                              code:status
                                      errorDetails:@"Failed to get validation cache read lock."
                                     correlationId:context.correlationId];
            
            completionBlock(NO, error);
        });
        
        return YES;
    }
    
    return [self checkCacheImpl:authority completionBlock:completionBlock];
}

// Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
// If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
// The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)validateAADAuthority:(NSURL *)authority
               requestParams:(ADRequestParameters *)requestParams
             completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    if ([self tryCheckCache:authority completionBlock:completionBlock])
    {
        return;
    }
    // If we can quickly grab the read lock on this cache then do so without having to jump threads
    if (pthread_rwlock_tryrdlock(&_rwLock) == 0)
    {
        __auto_type record = _validatedAADAuthorities[authority.adHostWithPortIfNecessary];
        pthread_rwlock_unlock(&_rwLock);
        
        if (record)
        {
            completionBlock(record.validated, record.error);
            return;
        }
    }
    
    // If we wither didn't have a cache, or couldn't get the read lock (which only happens if someone
    // has or is trying to get the write lock) then dispatch onto the AAD validation queue.
    dispatch_async(_aadValidationQueue, ^{
        
        if ([self checkCache:authority context:requestParams completionBlock:^(BOOL validated, ADAuthenticationError *error)
        {
            // Because we're on a serialized queue here to ensure that we don't have more then one
            // validation network request at a time, we want to jump off this queue as quick as
            // possible whenever we hit an error to unblock the queue
            
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                completionBlock(validated, error);
            });
        }])
        {
            return;
        }
        
        
        // If we didn't have anything in the cache then we need to hold onto the queue until we
        // get a response back from the server, or timeout, or fail for any other reason
        __block dispatch_semaphore_t dsem = dispatch_semaphore_create(0);
        
        [self requestAADValidation:authority
                     requestParams:requestParams
                   completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                 completionBlock(validated, error);
             });
             
             dispatch_semaphore_signal(dsem);
         }];
        
        // We're blocking the AAD Validation queue here so that we only process one authority validation
        // request at a time. As an application typically only uses a single AAD authority, this cuts
        // down on the amount of simultaneous requests that go out on multi threaded app launch
        // scenarios.
        if (dispatch_semaphore_wait(dsem, DISPATCH_TIME_NOW) != 0)
        {
            // Only bother logging if we have to wait on the queue.
            AD_LOG_INFO(@"Waiting on Authority Validation Queue", requestParams.correlationId, nil);
            dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
            AD_LOG_INFO(@"Returned from Authority Validation Queue", requestParams.correlationId, nil);
        }
    });
}


- (BOOL)getWriteLock:(id<ADRequestContext>)context
     completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    int status = pthread_rwlock_wrlock(&_rwLock);
    if (status != 0)
    {
        ADAuthenticationError *error =
        [ADAuthenticationError errorWithDomain:NSOSStatusErrorDomain
                                          code:status
                                  errorDetails:@"Failed to get validation cache write lock."
                                 correlationId:context.correlationId];
        
        completionBlock(NO, error);
        return NO;
    }
    
    return YES;
}

- (void)requestAADValidation:(NSURL *)authority
               requestParams:(ADRequestParameters *)requestParams
             completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    NSString *trustedHost = s_kTrustedAuthorityWorldWide;
    NSString *authorityHost = authority.adHostWithPortIfNecessary;
    if ([_whitelistedAADHosts containsObject:authorityHost])
    {
        trustedHost = authorityHost;
    }
    
    [ADAuthorityValidationRequest requestMetadataWithAuthority:authority.absoluteString
                                                   trustedHost:trustedHost
                                                       context:requestParams
                                               completionBlock:^(NSDictionary *response, ADAuthenticationError *error)
     {
         if (error)
         {
             completionBlock(NO, error);
             return;
         }
         
         NSString *oauthError = response[@"error"];
         if (oauthError)
         {
             ADAuthenticationError *adError =
             [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                    protocolCode:oauthError
                                                    errorDetails:response[@"error_details"]
                                                   correlationId:requestParams.correlationId];
             
             // If the error is something other than invalid_instance then something wrong is happening
             // on the server.
             if ([oauthError isEqualToString:@"invalid_instance"])
             {
                 if (![self getWriteLock:requestParams completionBlock:completionBlock])
                 {
                     return;
                 }
                 
                 ADAuthorityValidationAADRecord *record = [ADAuthorityValidationAADRecord new];
                 record.validated = NO;
                 record.error = adError;
                 _validatedAADAuthorities[authority.adHostWithPortIfNecessary] = record;
                 pthread_rwlock_unlock(&_rwLock);
             }
             
             completionBlock(NO, adError);
             return;
         }
         
         if (![self getWriteLock:requestParams completionBlock:completionBlock])
         {
             return;
         }
         
         NSArray<NSDictionary *> *metadata = response[@"metadata"];
         [self processMetadata:metadata];
         
         // In case the authority we were looking for wasn't in the metadata
         if (!_validatedAADAuthorities[authority.adHostWithPortIfNecessary])
         {
             ADAuthorityValidationAADRecord *record = [ADAuthorityValidationAADRecord new];
             record.validated = YES;
             
             _validatedAADAuthorities[authority.adHostWithPortIfNecessary] = record;
         }
         pthread_rwlock_unlock(&_rwLock);
         
         completionBlock(YES, nil);
     }];
}

- (void)processMetadata:(NSArray<NSDictionary *> *)metadata
{
    for (NSDictionary *environment in metadata)
    {
        ADAuthorityValidationAADRecord *record = [ADAuthorityValidationAADRecord new];
        record.validated = YES;
        record.networkHost = environment[@"preferred_network"];
        record.cacheHost = environment[@"preferred_cache"];
        
        NSArray *aliases = environment[@"aliases"];
        record.aliases = aliases;
        
        for (NSString *alias in aliases)
        {
            _validatedAADAuthorities[alias] = record;
        }
    }
}

#pragma mark - ADFS authority validation
- (void)validateADFSAuthority:(NSURL *)authority
                       domain:(NSString *)domain
                requestParams:(ADRequestParameters *)requestParams
              completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    // Check cache first
    if ([self isAuthorityValidated:authority domain:domain])
    {
        completionBlock(YES, nil);
        return;
    }
    
    // DRS discovery
    [self requestDrsDiscovery:domain
                      context:requestParams
              completionBlock:^(id result, ADAuthenticationError *error)
    {
        NSString *passiveAuthEndpoint = [self passiveEndpointFromDRSMetaData:result];

        if (!passiveAuthEndpoint)
        {
            if (!error)
            {
                error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                               protocolCode:nil
                                                               errorDetails:s_kDrsDiscoveryError
                                                              correlationId:requestParams.correlationId];
            }
            completionBlock(NO, error);
            return;
        }
        
        [self requestWebFingerValidation:passiveAuthEndpoint
                               authority:authority
                                 context:requestParams
                         completionBlock:^(BOOL validated, ADAuthenticationError *error)
        {
            if (validated)
            {
                [self addValidAuthority:authority domain:domain];
            }
            completionBlock(validated, error);
        }];
    }];
}

- (void)requestDrsDiscovery:(NSString *)domain
                    context:(id<ADRequestContext>)context
            completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock
{
    [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                               adfsType:AD_ADFS_ON_PREMS
                                                context:context
                                        completionBlock:^(id result, ADAuthenticationError *error)
     {
         if (result)
         {
             completionBlock(result, error);
             return;
         }
         
         [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                                    adfsType:AD_ADFS_CLOUD
                                                     context:context
                                             completionBlock:^(id result, ADAuthenticationError *error)
          {
              completionBlock(result, error);
          }];
     }];
}



- (void)requestWebFingerValidation:(NSString *)passiveAuthEndpoint
                         authority:(NSURL *)authority
                           context:(id<ADRequestContext>)context
                   completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    [ADWebFingerRequest requestWebFinger:passiveAuthEndpoint
                               authority:authority.absoluteString
                                 context:context
                         completionBlock:^(id result, ADAuthenticationError *error)
    {
                             
        BOOL validated = NO;
        if (result)
        {
            validated = [self isRealmTrustedFromWebFingerPayload:result
                                                       authority:authority];
        }
        
        if (!validated && !error)
        {
            error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                           protocolCode:nil
                                                           errorDetails:s_kWebFingerError
                                                          correlationId:[context correlationId]];
        }
        completionBlock(validated, error);
    }];
}

#pragma mark - Helper functions

- (NSString *)passiveEndpointFromDRSMetaData:(id)metaData
{
    return [[metaData objectForKey:@"IdentityProviderService"] objectForKey:@"PassiveAuthEndpoint"];
}


- (BOOL)isRealmTrustedFromWebFingerPayload:(id)json
                                 authority:(NSURL *)authority
{
    NSArray *links = [json objectForKey:@"links"];
    for (id link in links)
    {
        NSString *rel = [link objectForKey:@"rel"];
        NSString *target = [link objectForKey:@"href"];

        NSURL *targetURL = [NSURL URLWithString:target];
        
        if ([rel caseInsensitiveCompare:s_kTrustedRelation] == NSOrderedSame &&
            [targetURL isEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

@end

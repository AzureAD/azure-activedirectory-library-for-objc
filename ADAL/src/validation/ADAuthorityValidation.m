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

#import "MSIDAadAuthorityCache.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADAuthorityValidationRequest.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"
#import "ADAuthenticationError.h"
#import "ADAuthorityUtils.h"
#import "MSIDError.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDAuthority.h"
#import "NSURL+MSIDExtensions.h"

// Trusted relation for webFinger
static NSString* const s_kTrustedRelation              = @"http://schemas.microsoft.com/rel/trusted-realm";

// AAD validation check constant
static NSString* const s_kTenantDiscoveryEndpoint      = @"tenant_discovery_endpoint";

// DRS server error message constant
static NSString* const s_kDrsDiscoveryError            = @"DRS discovery was invalid or failed to return PassiveAuthEndpoint";
static NSString* const s_kWebFingerError               = @"WebFinger request was invalid or failed";



@implementation ADAuthorityValidation
{
    NSMutableDictionary *_validatedAdfsAuthorities;
    
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
    _aadCache = [MSIDAadAuthorityCache sharedInstance];
    
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
        if([url msidIsEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

#pragma mark - Authority validation

- (void)checkAuthority:(ADRequestParameters*)requestParams
     validateAuthority:(BOOL)validateAuthority
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
    if ([MSIDAuthority isADFSInstanceURL:authorityURL])
    {
        if (!validateAuthority)
        {
            completionBlock(NO, nil);
            return;
        }
        
        // Check for upn suffix
        NSString *upnSuffix = [ADHelpers getUPNSuffix:upn];
        if ([NSString msidIsStringNilOrBlank:upnSuffix])
        {
            error = [ADAuthenticationError errorFromArgument:upnSuffix
                                                argumentName:@"user principal name"
                                               correlationId:requestParams.correlationId];
            completionBlock(NO, error);
            return;
        }
        
        // Validate ADFS authority
        [self validateADFSAuthority:authorityURL
                             domain:upnSuffix
                      requestParams:requestParams
                    completionBlock:completionBlock];
    }
    else
    {
        // Validate AAD authority
        [self validateAADAuthority:authorityURL
                     requestParams:requestParams
                   completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             if (!validateAuthority && error && [error.protocolCode isEqualToString:@"invalid_instance"])
             {
                 error = nil;
             }
             completionBlock(validated, error);
         }];
    }
}

#pragma mark - AAD authority validation

// Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
// If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
// The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)validateAADAuthority:(NSURL *)authority
               requestParams:(ADRequestParameters *)requestParams
             completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    // We first try to get a record from the cache, this will return immediately if it couldn't
    // obtain a read lock
    MSIDAadAuthorityCacheRecord *record = [_aadCache tryCheckCache:authority.msidHostWithPortIfNecessary];
    if (record)
    {
        completionBlock(record.validated, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError: record.error]);
        return;
    }
    
    // If we wither didn't have a cache, or couldn't get the read lock (which only happens if someone
    // has or is trying to get the write lock) then dispatch onto the AAD validation queue.
    dispatch_async(_aadValidationQueue, ^{
        
        // If we didn't have anything in the cache then we need to hold onto the queue until we
        // get a response back from the server, or timeout, or fail for any other reason
        __block dispatch_semaphore_t dsem = dispatch_semaphore_create(0);
        
        [self requestAADValidation:authority
                     requestParams:requestParams
                   completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             
             // Because we're on a serialized queue here to ensure that we don't have more then one
             // validation network request at a time, we want to jump off this queue as quick as
             // possible whenever we hit an error to unblock the queue
             
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
            MSID_LOG_INFO(requestParams, @"Waiting on Authority Validation Queue");
            dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
            MSID_LOG_INFO(requestParams, @"Returned from Authority Validation Queue");
        }
    });
}

- (void)requestAADValidation:(NSURL *)authority
               requestParams:(ADRequestParameters *)requestParams
             completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    // Before we make the request, check the cache again, as these requests happen on a serial queue
    // and it's possible we were waiting on a request that got the information we're looking for.
    MSIDAadAuthorityCacheRecord *record = [_aadCache checkCache:authority.msidHostWithPortIfNecessary];
    if (record)
    {
        completionBlock(record.validated, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:record.error]);
        return;
    }
    
    NSString *trustedHost = ADTrustedAuthorityWorldWide;
    
    if ([ADAuthorityUtils isKnownHost:authority])
    {
        trustedHost = authority.msidHostWithPortIfNecessary;
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
         if (![NSString msidIsStringNilOrBlank:oauthError])
         {
             NSError *msidError =
             MSIDCreateError(MSIDErrorDomain, MSIDErrorAuthorityValidation, response[@"error_description"], oauthError, nil, nil, requestParams.correlationId, nil);
             
             // If the error is something other than invalid_instance then something wrong is happening
             // on the server.
             if ([oauthError isEqualToString:@"invalid_instance"])
             {
                 [_aadCache addInvalidRecord:authority oauthError:msidError context:requestParams];
             }
             
             completionBlock(NO, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError]);
             return;
         }
         
         
         NSError *msidError = nil;
         if (![_aadCache processMetadata:response[@"metadata"]
                               authority:authority
                                 context:requestParams
                                   error:&msidError])
         {
             completionBlock(NO, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError]);
             return;
         }
         
         completionBlock(YES, nil);
     }];
}

- (void)addInvalidAuthority:(NSString *)authority
{
    [_aadCache addInvalidRecord:[NSURL URLWithString:authority] oauthError:nil context:nil];
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
                    context:(id<MSIDRequestContext>)context
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
                           context:(id<MSIDRequestContext>)context
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
            [targetURL msidIsEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
}

@end

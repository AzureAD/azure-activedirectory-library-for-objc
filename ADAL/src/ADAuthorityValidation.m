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
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADHelpers.h"
#import "ADOAuth2Constants.h"
#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"
#import "NSURL+ADHelperMethods.h"


// Trusted relation for webFinger
static NSString* const s_kTrustedRelation              = @"http://schemas.microsoft.com/rel/trusted-realm";

// Trusted authorities
static NSString* const s_kTrustedAuthority             = @"https://login.windows.net";
static NSString* const s_kTrustedAuthorityChina        = @"https://login.chinacloudapi.cn";
static NSString* const s_kTrustedAuthorityGermany      = @"https://login.microsoftonline.de";
static NSString* const s_kTrustedAuthorityWorldWide    = @"https://login.microsoftonline.com";
static NSString* const s_kTrustedAuthorityUSGovernment = @"https://login-us.microsoftonline.com";

// AAD validation check constant
static NSString* const s_kTenantDiscoveryEndpoint      = @"tenant_discovery_endpoint";

// AAD authority validation error message constant
static NSString* const s_kValidationServerError        = @"The authority validation server returned an error.";
// DRS server error message constant
static NSString* const s_kDrsDiscoveryError            = @"DRS discovery was invalid or failed to return PassiveAuthEndpoint";
static NSString* const s_kWebFingerError               = @"WebFinger request was invalid or failed";

@implementation ADAuthorityValidation

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
    
    _validatedADAuthorities = [NSMutableSet new];
    //List of prevalidated authorities (Azure Active Directory cloud instances).
    //Only the sThrustedAuthority is used for validation of new authorities.
    [_validatedADAuthorities addObject:[NSURL URLWithString:s_kTrustedAuthority]];
    [_validatedADAuthorities addObject:[NSURL URLWithString:s_kTrustedAuthorityChina]]; // Microsoft Azure China
    [_validatedADAuthorities addObject:[NSURL URLWithString:s_kTrustedAuthorityGermany]]; // Microsoft Azure Germany
    [_validatedADAuthorities addObject:[NSURL URLWithString:s_kTrustedAuthorityWorldWide]]; // Microsoft Azure Worldwide
    [_validatedADAuthorities addObject:[NSURL URLWithString:s_kTrustedAuthorityUSGovernment]]; // Microsoft Azure US Government
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_validatedADAuthorities);
    _validatedADAuthorities = nil;
    
    SAFE_ARC_RELEASE(_validatedAdfsAuthorities);
    _validatedAdfsAuthorities = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
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

- (BOOL)addValidAuthority:(NSURL *)authority
{
    if (!authority)
    {
        return NO;
    }
    [_validatedADAuthorities addObject:authority];
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
    for (NSURL *url in _validatedADAuthorities)
    {
        if([url isEquivalentAuthority:authority])
        {
            return YES;
        }
    }
    return NO;
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



#pragma mark - AAD authority validation
//Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
//If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
//The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)validateAADAuthority:(NSURL *)authority
               requestParams:(ADRequestParameters *)requestParams
             completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    // Check cache
    if ([self isAuthorityValidated:authority])
    {
        completionBlock(YES, nil);
        return;
    }
    
    [ADAuthorityValidationRequest requestAuthorityValidationForAuthority:authority.absoluteString
                                                        trustedAuthority:s_kTrustedAuthority
                                                                 context:requestParams
                                                         completionBlock:^(id response, ADAuthenticationError *error)
    {
        BOOL verified = ![NSString adIsStringNilOrBlank:[response objectForKey:s_kTenantDiscoveryEndpoint]];
        if (!verified)
        {
            //First check for explicit OAuth2 protocol error:
            NSString* serverOAuth2Error = [response objectForKey:OAUTH2_ERROR];
            NSString* errorDetails = [response objectForKey:OAUTH2_ERROR_DESCRIPTION];
            // Error response from the server
            errorDetails = errorDetails ? errorDetails : [NSString stringWithFormat:@"%@ - %@", s_kValidationServerError, serverOAuth2Error];
            
            error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                           protocolCode:serverOAuth2Error
                                                           errorDetails:errorDetails
                                                          correlationId:requestParams.correlationId];
        }
        else
        {
            [self addValidAuthority:authority];
        }
        
        completionBlock(verified, error);
    }];
}



#pragma mark - ADFS authority validation
- (void)validateADFSAuthority:(NSURL *)authority
                       domain:(NSString *)domain
                requestParams:(ADRequestParameters *)requestParams
              completionBlock:(ADAuthorityValidationCallback)completionBlock
{
    // Check cache first
    if([self isAuthorityValidated:authority domain:domain])
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

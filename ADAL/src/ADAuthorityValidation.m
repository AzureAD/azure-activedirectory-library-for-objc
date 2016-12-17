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
#import "ADWebFingerRequest.h"
#import "ADAuthorityValidationRequest.h"
#import "ADOAuth2Constants.h"
#import "ADHelpers.h"

static NSString* const s_kTrustedRelation = @"http://schemas.microsoft.com/rel/trusted-realm";

static NSString* const s_kTrustedAuthority = @"https://login.windows.net";
static NSString* const s_kTrustedAuthorityChina = @"https://login.chinacloudapi.cn";
static NSString* const s_kTrustedAuthorityGermany = @"https://login.microsoftonline.de";
static NSString* const s_kTrustedAuthorityWorldWide = @"https://login.microsoftonline.com";
static NSString* const s_kTrustedAuthorityUSGovernment = @"https://login-us.microsoftonline.com";

static NSString* const s_kTenantDiscoveryEndpoint = @"tenant_discovery_endpoint";

static NSString* const s_kValidationServerError = @"The authority validation server returned an error.";


@implementation ADAuthorityValidation

@synthesize telemetryRequestId = _telemetryRequestId;
@synthesize correlationId = _correlationId;

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
    if (!self) {
        return nil;
    }
    
    _validatedAdfsAuthorities = [NSMutableDictionary new];
    
    _validatedADAuthorities = [NSMutableSet new];
    //List of prevalidated authorities (Azure Active Directory cloud instances).
    //Only the sThrustedAuthority is used for validation of new authorities.
    [_validatedADAuthorities addObject:s_kTrustedAuthority];
    [_validatedADAuthorities addObject:s_kTrustedAuthorityChina]; // Microsoft Azure China
    [_validatedADAuthorities addObject:s_kTrustedAuthorityGermany]; // Microsoft Azure Germany
    [_validatedADAuthorities addObject:s_kTrustedAuthorityWorldWide]; // Microsoft Azure Worldwide
    [_validatedADAuthorities addObject:s_kTrustedAuthorityUSGovernment]; // Microsoft Azure US Government
    
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
- (BOOL)addValidAuthority:(NSString *)authority domain:(NSString *)domain
{
    // Get authority mapping or create one if one does not exist
    NSMutableSet *set = [_validatedAdfsAuthorities objectForKey:authority];
    if (!set)
    {
        set = [NSMutableSet new];
        [_validatedAdfsAuthorities setObject:set forKey:authority];
    }
    
    // Add domain to the set of valid domains for the authority
    [set addObject:domain];
    
    return YES;
}

- (BOOL)addValidAuthority:(NSString *)authorityHost
{
    if ([NSString adIsStringNilOrBlank:authorityHost])
    {
        return NO;
    }
    [_validatedADAuthorities addObject:authorityHost];
    return YES;
}


- (BOOL)isAuthorityValidated:(NSString *)authority domain:(NSString *)domain
{
    // Check for authority
    NSSet *domains = [_validatedAdfsAuthorities objectForKey:authority];
    if ([domains containsObject:domain])
    {
        return YES;
    }
    
    return NO;
}

// Checks the cache for previously validated authority.
// Note that the authority host should be normalized: no ending "/" and lowercase.
- (BOOL)isAuthorityValidated:(NSString *)authorityHost
{
    if (!authorityHost)
    {
        return NO;
    }
    
    BOOL validated = [_validatedADAuthorities containsObject:authorityHost];
    return validated;
}

#pragma mark - Authority validation
- (void)validateAuthority:(NSString *)authority
          completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    [self validateAuthority:authority upn:nil completionBlock:completionBlock];
}

- (void)validateAuthority:(NSString *)authority
                      upn:(NSString *)upn
          completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    // TODO: Check for valid authority
    
    
    
    
    ADAuthenticationError *authorityCheckError = nil;
    
    NSString *authorityHost = [ADHelpers extractHost:authority correlationId:_correlationId error:&authorityCheckError];
    if (!authorityHost)
    {
        completionBlock(NO, authorityCheckError);
        return;
    }
    
    
    // Check for AAD or ADFS
    if ([ADHelpers isADFSInstance:authority])
    {
        // Check for upn suffix
        NSString *upnSuffix = [ADHelpers getUPNSuffix:upn];
        if ([NSString adIsStringNilOrBlank:upnSuffix])
        {
            ADAuthenticationError *adError = [ADAuthenticationError errorFromArgument:upnSuffix
                                                                         argumentName:@"user principal name"
                                                                        correlationId:_correlationId];
            completionBlock(NO, adError);
            return;
        }
        
        // Check cache
        if ([self isAuthorityValidated:authority domain:upnSuffix])
        {
            completionBlock(YES, nil);
            return;
        }
        
        // Try authority validation
        [self validateADFSAuthority:authority domain:upnSuffix completionBlock:completionBlock];
    }
    
    else
    {
        // Check for cache
        if ([self isAuthorityValidated:authorityHost])
        {
            completionBlock(YES, nil);
            return;
        }
        
        // Try authority validation
        [self validateAuthority:authority authorityHost:authorityHost completionBlock:completionBlock];
    
    }
}



#pragma mark - AAD authority validation
//Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
//If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
//The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)validateAuthority:(NSString *)authority
            authorityHost:authorityHost
          completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    // Check cache
    if ([self isAuthorityValidated:authority.lowercaseString]) {
        completionBlock(YES, nil);
        return;
    }
    
    [ADAuthorityValidationRequest requestAuthorityValidationForAuthority:authority
                                                        trustedAuthority:s_kTrustedAuthority
                                                                 context:self
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
                                                          correlationId:_correlationId];
        }
        else
        {
            [self addValidAuthority:authorityHost];
        }
        
        completionBlock(verified, error);
    }];
}



#pragma mark - ADFS authority validation
- (void)validateADFSAuthority:(NSString *)authority
                       domain:(NSString *)domain
              completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    // Check cache first
    if([self isAuthorityValidated:authority domain:domain])
    {
        completionBlock(YES, nil);
        return;
    }
    
    
    
    // DRS discovery
    [self requestDrsDiscovery:domain
              completionBlock:^(id result, ADAuthenticationError *error)
    {
        if (result)
        {
            [self requestWebFingerWithMetaData:result
                                     authority:authority
                               completionBlock:^(BOOL validated, ADAuthenticationError *error) {
                                   if (validated)
                                   {
                                       [self addValidAuthority:authority domain:domain];
                                   }
                                   completionBlock(validated, error);
                               }];
        }
        else
        {
            if (!error)
            {
                error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                               protocolCode:nil
                                                               errorDetails:@"DRS discovery failure"
                                                              correlationId:_correlationId];
            }
            completionBlock(NO, error);
        }
    }];
}

- (void)requestDrsDiscovery:(NSString *)domain
            completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock
{
    [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                               adfsType:AD_ADFS_ON_PREMS
                                                context:self
                                        completionBlock:^(id result, ADAuthenticationError *error) {
                                            if (!result)
                                            {
                                                [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                                                                           adfsType:AD_ADFS_CLOUD
                                                                                            context:self
                                                                                    completionBlock:^(id result, ADAuthenticationError *error) {
                                                                                        completionBlock(result, error);
                                                                                    }];
                                            }
                                            else
                                            {
                                                completionBlock(result, error);
                                            }
                                        }];
}



- (void)requestWebFingerWithMetaData:(id)metaData
                           authority:(NSString *)authority
                     completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    ADAuthenticationError *error = nil;
    NSString *passiveEndpoint = [self passiveEndpointFromDRSMetaData:metaData];
    if ([NSString adIsStringNilOrBlank:passiveEndpoint])
    {
        NSString *errorMessage = @"PassiveAuthEndpoint not found in DRS discovery payload";
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                       protocolCode:nil
                                                       errorDetails:errorMessage
                                                      correlationId:_correlationId];
        completionBlock(NO, error);
    }
    else
    {
        [ADWebFingerRequest requestWebFinger:passiveEndpoint
                                   authority:authority
                                     context:self
                             completionBlock:^(id result, ADAuthenticationError *error) {
                                 
                                 BOOL validated = NO;
                                 if (result)
                                 {
                                     validated = [self isRealmTrustedFromWebFingerPayload:result
                                                                                authority:authority];
                                 }
                                 completionBlock(validated, error);
                             }];
    }
}

#pragma mark - Helper functions

- (NSString*)passiveEndpointFromDRSMetaData:(id)metaData
{
    return [[metaData objectForKey:@"IdentityProviderService"] objectForKey:@"PassiveAuthEndpoint"];
}

- (BOOL)isRealmTrustedFromWebFingerPayload:(id)json
                                 authority:(NSString *)authority
{
    NSArray *links = [json objectForKey:@"links"];
    for (id link in links)
    {
        NSString *rel = [link objectForKey:@"rel"];
        NSString *target = [link objectForKey:@"href"];
        
        NSURL *authorityURL = [NSURL URLWithString:authority];
        NSString *authorityHost = [NSString stringWithFormat:@"%@://%@", authorityURL.scheme, authorityURL.host];
        
        if ([rel caseInsensitiveCompare:s_kTrustedRelation] == NSOrderedSame &&
            [target caseInsensitiveCompare:authorityHost] == NSOrderedSame)
        {
            return YES;
        }
    }
    return NO;
}

@end

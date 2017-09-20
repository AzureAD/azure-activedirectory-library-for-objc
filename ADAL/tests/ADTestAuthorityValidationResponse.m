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

#import "ADTestAuthorityValidationResponse.h"
#import "ADAuthorityValidationRequest.h"
#import "ADOAuth2Constants.h"

#import "NSDictionary+ADExtensions.h"
#import "NSDictionary+ADTestUtil.h"
#import "NSURL+ADExtensions.h"


#define DEFAULT_TRUSTED_HOST "login.microsoftonline.com"

@implementation ADTestAuthorityValidationResponse

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
{
    return [self validAuthority:authority withMetadata:nil];
}

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                         withMetadata:(NSArray *)metadata
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://" DEFAULT_TRUSTED_HOST "/common/discovery/instance?api-version=" AAD_AUTHORITY_VALIDATION_API_VERSION "&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, [authority lowercaseString]];
    ADTestURLResponse *response = [ADTestURLResponse new];
    response.requestURL = [NSURL URLWithString:authorityValidationURL];
    [response setResponseURL:@"https://idontmatter.com" code:200 headerFields:@{}];
    if (metadata)
    {
        [response setResponseJSON:@{@"tenant_discovery_endpoint" : @"totally valid!", @"metadata" : metadata}];
    }
    else
    {
        [response setResponseJSON:@{@"tenant_discovery_endpoint" : @"totally valid!"}];
    }
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

+ (ADTestURLResponse *)invalidAuthority:(NSString *)authority
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://" DEFAULT_TRUSTED_HOST "/common/discovery/instance?api-version=" AAD_AUTHORITY_VALIDATION_API_VERSION "&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, [authority lowercaseString]];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:authorityValidationURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{OAUTH2_ERROR : @"invalid_instance",
                                                                        OAUTH2_ERROR_DESCRIPTION : @" I'm an OAUTH error description!"}];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

+ (ADTestURLResponse *)validDrsPayload:(NSString *)domain
                               onPrems:(BOOL)onPrems
         passiveAuthenticationEndpoint:(NSString *)passiveAuthEndpoint
{
    NSString* validationPayloadURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                                      onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:validationPayloadURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"DeviceRegistrationService" :
                                                                            @{@"RegistrationEndpoint" : @"https://idontmatter.com/EnrollmentServer/DeviceEnrollmentWebService.svc",
                                                                              @"RegistrationResourceId" : @"urn:ms-drs:UUID"
                                                                              },
                                                                        @"AuthenticationService" :
                                                                            @{@"AuthCodeEndpoint" : @"https://idontmatter.com/adfs/oauth2/authorize",
                                                                              @"TokenEndpoint" : @"https://idontmatter.com/adfs/oauth2/token"
                                                                              },
                                                                        @"IdentityProviderService" :
                                                                            @{@"PassiveAuthEndpoint" : passiveAuthEndpoint}
                                                                        }];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}


+ (ADTestURLResponse *)invalidDrsPayload:(NSString *)domain
                                 onPrems:(BOOL)onPrems
{
    NSString* validationPayloadURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                                      onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:validationPayloadURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{}];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}


+ (ADTestURLResponse *)unreachableDrsService:(NSString *)domain
                                     onPrems:(BOOL)onPrems
{
    NSString *drsURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                        onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    ADTestURLResponse *response = [ADTestURLResponse serverNotFoundResponseForURLString:drsURL];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}


+ (ADTestURLResponse *)validWebFinger:(NSString *)passiveEndpoint
                            authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"subject" : authority,
                                                                        @"links" : @[@{
                                                                                         @"rel" : @"http://schemas.microsoft.com/rel/trusted-realm",
                                                                                         @"href" : authority
                                                                                         }]
                                                                        }];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

+ (ADTestURLResponse *)invalidWebFinger:(NSString *)passiveEndpoint
                              authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{}];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

+ (ADTestURLResponse *)invalidWebFingerNotTrusted:(NSString *)passiveEndpoint
                                        authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"subject" : authority,
                                                                        @"links" : @[@{
                                                                                         @"rel" : @"http://schemas.microsoft.com/rel/trusted-realm",
                                                                                         @"href" : @"idontmatch.com"
                                                                                         }]
                                                                        }];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

+ (ADTestURLResponse*)unreachableWebFinger:(NSString *)passiveEndpoint
                                 authority:(NSString *)authority
{
    (void)authority;
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse *response = [ADTestURLResponse serverNotFoundResponseForURLString:url];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    return response;
}

@end

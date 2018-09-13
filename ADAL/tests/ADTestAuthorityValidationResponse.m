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

#import "ADTestAuthorityValidationResponse.h"
#import "ADAuthorityValidationRequest.h"

#import "NSDictionary+MSIDTestUtil.h"


#define DEFAULT_TRUSTED_HOST @"login.microsoftonline.com"

@implementation ADTestAuthorityValidationResponse

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
{
    return [self validAuthority:authority withMetadata:nil];
}

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                         withMetadata:(NSArray *)metadata
{
    return [self validAuthority:authority trustedHost:DEFAULT_TRUSTED_HOST withMetadata:metadata];
}

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                          trustedHost:(NSString *)trustedHost
                         withMetadata:(NSArray *)metadata
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://%@/common/discovery/instance?api-version=" AAD_AUTHORITY_VALIDATION_API_VERSION "&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, trustedHost, [authority lowercaseString]];
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
    return [self invalidAuthority:authority trustedHost:DEFAULT_TRUSTED_HOST];
}

+ (ADTestURLResponse*)invalidAuthority:(NSString *)authority
                           trustedHost:(NSString *)trustedHost
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://%@/common/discovery/instance?api-version=" AAD_AUTHORITY_VALIDATION_API_VERSION "&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, trustedHost, [authority lowercaseString]];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:authorityValidationURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{MSID_OAUTH2_ERROR : @"invalid_instance",
                                                                        MSID_OAUTH2_ERROR_DESCRIPTION : @" I'm an OAUTH error description!"}];
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

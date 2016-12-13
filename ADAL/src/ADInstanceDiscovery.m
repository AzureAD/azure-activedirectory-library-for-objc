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

#import "ADAL_Internal.h"
#import "ADInstanceDiscovery.h"
#import "ADAuthenticationError.h"
#import "ADWebRequest.h"
#import "ADAuthenticationError.h"
#import "NSDictionary+ADExtensions.h"
#import "ADWebResponse.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"
#import "NSString+ADHelperMethods.h"
#import "ADClientMetrics.h"
#import "ADUserIdentifier.h"
#import "ADHelpers.h"

static NSString* const sTrustedAuthority = @"https://login.windows.net";
static NSString* const sApiVersionKey = @"api-version";
static NSString* const sApiVersion = @"1.0";
static NSString* const sAuthorizationEndPointKey = @"authorization_endpoint";
static NSString* const sTenantDiscoveryEndpoint = @"tenant_discovery_endpoint";

static NSString* const sValidationServerError = @"The authority validation server returned an error: %@.";

static NSString* const sADFSCloudBase = @"https://enterpriseregistration.windows.net/";
static NSString* const sADFSOnPremsBase = @"https://enterpriseregistration.";
static NSString* const sADFSSuffix = @"/enrollmentserver/contract?api-version=1.0";

static NSString* const sWebFinger = @".well-known/webfinger?";

@implementation ADInstanceDiscovery

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    _validatedAuthorities = [NSMutableSet new];
    //List of prevalidated authorities (Azure Active Directory cloud instances).
    //Only the sThrustedAuthority is used for validation of new authorities.
    [_validatedAuthorities addObject:sTrustedAuthority];
    [_validatedAuthorities addObject:@"https://login.chinacloudapi.cn"]; // Microsoft Azure China
    [_validatedAuthorities addObject:@"https://login.microsoftonline.de"]; // Microsoft Azure Germany
    [_validatedAuthorities addObject:@"https://login.microsoftonline.com"]; // Microsoft Azure Worldwide
    [_validatedAuthorities addObject:@"https://login-us.microsoftonline.com"]; // Microsoft Azure US Government
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_validatedAuthorities);
    _validatedAuthorities = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

/*! The getter of the public "validatedAuthorities" property. */
- (NSSet*)validatedAuthorities
{
    API_ENTRY;
    return _validatedAuthorities;
}

+ (ADInstanceDiscovery*)sharedInstance
{
    API_ENTRY;
    static dispatch_once_t once;
    static ADInstanceDiscovery* singleton = nil;
    
    dispatch_once(&once, ^{
        singleton = [[ADInstanceDiscovery alloc] init];
    });
    
    return singleton;
}

/*! Extracts the base URL host, e.g. if the authority is
 "https://login.windows.net/mytenant.com/oauth2/authorize", the host will be
 "https://login.windows.net". Returns nil and reaises an error if the protocol
 is not https or the authority is not a valid URL.*/
- (NSString*)extractHost:(NSString *)authority
           correlationId:(NSUUID *)correlationId
                   error:(ADAuthenticationError * __autoreleasing *)error
{
    NSURL* fullUrl = [NSURL URLWithString:authority.lowercaseString];
    
    ADAuthenticationError* adError = nil;
    if (!fullUrl || ![fullUrl.scheme isEqualToString:@"https"])
    {
        adError = [ADAuthenticationError errorFromArgument:authority argumentName:@"authority" correlationId:correlationId];
    }
    else
    {
        NSArray* paths = fullUrl.pathComponents;
        if (paths.count < 2)
        {
            adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                                             protocolCode:nil
                                                             errorDetails:@"Missing tenant in the authority URL. Please add the tenant or use 'common', e.g. https://login.windows.net/example.com."
                                                            correlationId:correlationId];
        }
    }
    
    if (adError)
    {
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    
    return [NSString stringWithFormat:@"https://%@", fullUrl.host];
}


/*! Checks whether the authority is an ADFS or not by looking for "adfs" in the the url path.
 e.g./ "https://.../adfs", or "https://.../adfs/...". */
- (BOOL)isADFS:(NSString *)authority
{
    NSURL *fullUrl = [NSURL URLWithString:authority.lowercaseString];
    NSArray *paths = fullUrl.pathComponents;
    
    if (paths.count < 2)
    {
        return NO;
    }
    else {
        NSString *tenant = [paths objectAtIndex:1];
        if ([@"adfs" isEqualToString:tenant])
        {
            return YES;
        }
        return NO;
    }
}


- (void)validateAuthority:(NSString *)authority
            requestParams:(ADRequestParameters*)requestParams
          completionBlock:(ADDiscoveryCallback)completionBlock;
{
    API_ENTRY;
    THROW_ON_NIL_ARGUMENT(completionBlock);
    NSUUID* correlationId = [requestParams correlationId];
    
    NSString* message = [NSString stringWithFormat:@"Attempting to validate the authority: %@; CorrelationId: %@", authority, [correlationId UUIDString]];
    AD_LOG_VERBOSE(@"Instance discovery", [requestParams correlationId], message);
    
    authority = [authority lowercaseString];
    
    ADAuthenticationError* error = nil;
    NSString* authorityHost = [self extractHost:authority correlationId:correlationId error:&error];
    if (!authorityHost)
    {
        completionBlock(NO, error);
        return;
    }
    
    //Cache poll:
    if ([self isAuthorityValidated:authorityHost])
    {
        completionBlock(YES, nil);
        return;
    }

    //Nothing in the cache, ask the server:
    if ([self isADFS:authority])
    {
        [self requestValidationOfADFSAuthority:authority
                                      adfsType:AD_ADFS_AUTO
                                 requestParams:requestParams
                               completionBlock:completionBlock];
    }
    else
    {
        [self requestValidationOfAuthority:authority
                                      host:authorityHost
                          trustedAuthority:sTrustedAuthority
                             requestParams:requestParams
                           completionBlock:completionBlock];
    }
}


//Checks the cache for previously validated authority.
//Note that the authority host should be normalized: no ending "/" and lowercase.
- (BOOL)isAuthorityValidated:(NSString *)authorityHost
{
    if (!authorityHost)
    {
        return NO;
    }
    
    BOOL validated = [_validatedAuthorities containsObject:authorityHost];
    
    NSString* message = [NSString stringWithFormat:@"Checking cache for '%@'. Result: %d", authorityHost, validated];
    AD_LOG_VERBOSE(@"Authority Validation Cache", nil, message);
    return validated;
}

//Note that the authority host should be normalized: no ending "/" and lowercase.
- (BOOL)addValidAuthority:(NSString *)authorityHost
{
    if ([NSString adIsStringNilOrBlank:authorityHost])
    {
        return NO;
    }
    
    [_validatedAuthorities addObject:authorityHost];
    
    NSString* message = [NSString stringWithFormat:@"Setting validation set to YES for authority '%@'", authorityHost];
    AD_LOG_VERBOSE(@"Authority Validation Cache", nil, message);
    return YES;
}


//Processes web response. Checks for accepted codes and returns a JSON object if possible.
- (id)getJsonFromWebResponse:(ADWebResponse *)webResponse
               correlationId:(NSUUID *)correlationId
         acceptedStatusCodes:(NSArray *)acceptedStatusCodes
                       error:(ADAuthenticationError **)error
{
    THROW_ON_NIL_ARGUMENT(webResponse)
    THROW_ON_NIL_ARGUMENT(correlationId)
    
    NSNumber *code = [NSNumber numberWithInteger:webResponse.statusCode];
    if (![acceptedStatusCodes containsObject:code])
    {
        NSString* logMessage = [NSString stringWithFormat:@"Server HTTP Status %ld", (long)webResponse.statusCode];
        NSString* responseBodyString = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
        SAFE_ARC_AUTORELEASE(responseBodyString);
        NSString* errorData = [NSString stringWithFormat:@"Server HTTP Response %@", responseBodyString];
        AD_LOG_WARN(logMessage, correlationId, errorData);

        if (error)
        {
            *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                            protocolCode:nil
                                                            errorDetails:errorData
                                                           correlationId:correlationId];
        }
        
        return nil;
    }
    
    NSError   *jsonError  = nil;
    id         jsonObject = [NSJSONSerialization JSONObjectWithData:webResponse.body options:0 error:&jsonError];
    
    if (!jsonObject)
    {
        NSString* details = jsonError ? jsonError.localizedDescription : @"No JSON object was in the web response data";
        
        if (error)
        {
            *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                            protocolCode:nil
                                                            errorDetails:details
                                                           correlationId:correlationId];
        }
        
        return nil;
    }

    return jsonObject;
}


- (ADAuthenticationError *)addValidAuthoritiesFromWebReponse:(ADWebResponse *)webResponse
                                               authorityHost:(NSString *)authorityHost
                                               correlationId:(NSUUID *)correlationId
{
    ADAuthenticationError *adError = nil;
    id jsonObject = [self getJsonFromWebResponse:webResponse
                                   correlationId:correlationId
                             acceptedStatusCodes:@[@200, @400, @401]
                                           error:&adError];
    
    if (adError)
    {
        return adError;
    }

    if (![jsonObject isKindOfClass:[NSDictionary class]])
    {
        NSString* errorMessage = [NSString stringWithFormat:@"Unexpected object type: %@", [jsonObject class]];
        
        adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                         protocolCode:nil
                                                         errorDetails:errorMessage
                                                        correlationId:correlationId];
    
        return adError;
    }
    
    // Load the response
    NSDictionary* response = (NSDictionary *)jsonObject;
    AD_LOG_VERBOSE(@"Discovery response", correlationId, response.description);
    BOOL verified = ![NSString adIsStringNilOrBlank:[response objectForKey:sTenantDiscoveryEndpoint]];
    if (!verified)
    {
        //First check for explicit OAuth2 protocol error:
        NSString* serverOAuth2Error = [response objectForKey:OAUTH2_ERROR];
        NSString* errorDetails = [response objectForKey:OAUTH2_ERROR_DESCRIPTION];
        // Error response from the server
        errorDetails = errorDetails ? errorDetails : [NSString stringWithFormat:sValidationServerError, serverOAuth2Error];
        return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                      protocolCode:serverOAuth2Error
                                                      errorDetails:errorDetails
                                                     correlationId:correlationId];
    }
    
    [self addValidAuthority:authorityHost];
    return nil;
}


//Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
//If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
//The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)requestValidationOfAuthority:(NSString *)authority
                                host:(NSString *)authorityHost
                    trustedAuthority:(NSString *)trustedAuthority
                       requestParams:(ADRequestParameters*)requestParams
                     completionBlock:(ADDiscoveryCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    NSUUID* correlationId = [requestParams correlationId];
    THROW_ON_NIL_ARGUMENT(correlationId);//Should be set by the caller
    
    //All attempts to complete are done. Now try to validate the authorization ednpoint:
    NSString* authorizationEndpoint = [authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX];
    
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         sApiVersion, sApiVersionKey,
                                         authorizationEndpoint, sAuthorizationEndPointKey,
                                         nil];
    
    NSString* endPoint = [NSString stringWithFormat:@"%@/%@?%@",
                          trustedAuthority, OAUTH2_INSTANCE_DISCOVERY_SUFFIX, [request_data adURLFormEncode]];
    
    AD_LOG_VERBOSE(@"Authority Validation Request", correlationId, endPoint);
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:[NSURL URLWithString:endPoint]
                                                         context:requestParams];
    
    [webRequest setIsGetRequest:YES];
    [webRequest.headers setObject:@"application/json" forKey:@"Accept"];
    [webRequest.headers setObject:@"application/x-www-form-urlencoded" forKey:@"Content-Type"];
    __block NSDate* startTime = [NSDate new];
    [[ADClientMetrics getInstance] addClientMetrics:webRequest.headers endpoint:endPoint];
    
    [webRequest send:^( NSError *error, ADWebResponse *webResponse )
    {
        ADAuthenticationError* adError = nil;
        if (error)
        {
            AD_LOG_WARN(@"System error while making request.", correlationId, error.description);
            adError = [ADAuthenticationError errorFromNSError:error
                                                 errorDetails:error.localizedDescription
                                                correlationId:correlationId];
        }
        else
        {
            adError = [self addValidAuthoritiesFromWebReponse:webResponse
                                                authorityHost:authorityHost
                                                correlationId:correlationId];
        }
        
        NSString* errorDetails = [adError errorDetails];
        [[ADClientMetrics getInstance] endClientMetricsRecord:endPoint
                                                    startTime:startTime
                                                correlationId:correlationId
                                                 errorDetails:errorDetails];
        SAFE_ARC_RELEASE(startTime);
        
        completionBlock(!adError, adError);
     }];
}


//Checks validity of the ADFS authority by checking for passive authentication endpoint
//from DRS discovery and then using the webFinger to validate the authority.
- (void)requestValidationOfADFSAuthority:(NSString *)authority
                                adfsType:(ADFSType)adfsType
                           requestParams:(ADRequestParameters *)requestParams
                         completionBlock:(ADDiscoveryCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    THROW_ON_NIL_ARGUMENT(requestParams);
    THROW_ON_NIL_ARGUMENT(authority);
    
    NSString *upn = [requestParams.identifier userId];
    NSUUID *correlationId = [requestParams correlationId];//Should be set by the caller
    THROW_ON_NIL_ARGUMENT(correlationId);
    
    NSString *upnSuffix = [ADHelpers getUPNSuffix:upn];
    AD_LOG_VERBOSE(@"Authority Validation for ADFS", correlationId, upnSuffix);
    
    if (!upnSuffix)
    {
        ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:upn
                                                                   argumentName:@"user principal name"
                                                                  correlationId:correlationId];
        completionBlock(NO, error);
        return;
    }
    
    // DRS payload process
    [self requestDRSDiscovery:upnSuffix
                     adfsType:adfsType
                      context:requestParams
            completionHandler:^(id drsMetaData, NSError *error)
    {
        if (error)
        {
            AD_LOG_WARN(@"Error while making DRS discovery request.", correlationId, error.description);
            ADAuthenticationError *adError = [ADAuthenticationError errorFromNSError:error
                                                                        errorDetails:error.localizedDescription
                                                                       correlationId:correlationId];
            completionBlock(NO, adError);
        }
        else
        {
            NSString *passiveEndPoint = [self passiveEndpointFromDRSMetaData:drsMetaData];
            if ([NSString adIsStringNilOrBlank:passiveEndPoint])
            {
                ADAuthenticationError *adError = [ADAuthenticationError
                                                    errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                                    protocolCode:nil
                                                                    errorDetails:@"DRS discovery meta data doesnot contain passiveAuthEndpoint"
                                                                   correlationId:correlationId];
                completionBlock(NO, adError);
            }
            else
            {
                [self validateWithWebfingerForAuthority:authority
                                    passiveAuthEndpoint:passiveEndPoint
                                                context:requestParams
                                      completionHandler:^(BOOL validated, ADAuthenticationError *error) {
                                          completionBlock(validated, error);
                                      }];
            }
        }
        
    }];
}


- (void)requestDRSDiscovery:(NSString *)upnSuffix
                   adfsType:(ADFSType)adfsType
                    context:(id<ADRequestContext>)context
          completionHandler:(void (^)(id drsMetaData, NSError *error))completionHandler
{
    THROW_ON_NIL_ARGUMENT(context);
    THROW_ON_NIL_ARGUMENT(upnSuffix);

    NSUUID *correlationId = [context correlationId];
    THROW_ON_NIL_ARGUMENT(correlationId);

    AD_LOG_VERBOSE(@"Requesting DRS payload", correlationId, upnSuffix);
    
    NSURL *onPremsURL = [NSURL URLWithString:
                         [NSString stringWithFormat:@"%@%@%@", sADFSOnPremsBase, upnSuffix, sADFSSuffix]];
    NSURL *cloudURL = [NSURL URLWithString:
                       [NSString stringWithFormat:@"%@%@%@", sADFSCloudBase, upnSuffix, sADFSSuffix]];

    if (adfsType == AD_ADFS_AUTO)
    {
        [self tryRequestDRSDiscovery:onPremsURL
                             context:context
                   completionHandler:^(id drsMetaData, NSError *error)
        {
                       
            if (error)
            {
                [self tryRequestDRSDiscovery:cloudURL
                                     context:context
                           completionHandler:^(id drsMetaData, NSError *error)
                 {
                     completionHandler(drsMetaData, error);
                 }];
            }
            else
            {
                completionHandler(drsMetaData, nil);
            }
        }];
    }
    else
    {
        NSURL *url = nil;
        if (adfsType == AD_ADFS_ON_PREMS)
        {
            url = onPremsURL;
        }
        else
        {
            url = cloudURL;
        }
        
        [self tryRequestDRSDiscovery:url
                             context:context
                   completionHandler:^(id drsMetaData, NSError *error)
        {
            completionHandler(drsMetaData, error);
        }];
    }
}


- (void)tryRequestDRSDiscovery:(NSURL *)url
                       context:(id<ADRequestContext>)context
             completionHandler:(void (^)(id drsMetaData, NSError *error))completionHandler {
    
    THROW_ON_NIL_ARGUMENT(url)
    THROW_ON_NIL_ARGUMENT(context)

    NSUUID *correlationId = [context correlationId];
    THROW_ON_NIL_ARGUMENT(correlationId);

    AD_LOG_VERBOSE(@"Request for DRS discovery", correlationId, url.absoluteString);
    
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:url context:context];
    [webRequest setIsGetRequest:YES];
    [webRequest.headers setObject:@"application/json" forKey:@"Accept"];
    
    __block NSDate* startTime = [NSDate new];
    [[ADClientMetrics getInstance] addClientMetrics:webRequest.headers endpoint:url.absoluteString];
    
    [webRequest send:^(NSError *error, ADWebResponse *webResponse)
    {
        id jsonObject = nil;
        NSError *webRequestError = nil;
        
        if (error)
        {
            AD_LOG_WARN(@"System error while making request.", correlationId, error.description);
            webRequestError = error;
        }
        else
        {
            jsonObject = [self getJsonFromWebResponse:webResponse
                                        correlationId:correlationId
                                  acceptedStatusCodes:@[@200]
                                                error:&webRequestError];
        }
        
        NSString* errorDetails = [webRequestError localizedDescription];
        [[ADClientMetrics getInstance] endClientMetricsRecord:url.absoluteString
                                                    startTime:startTime
                                                correlationId:correlationId
                                                 errorDetails:errorDetails];
        SAFE_ARC_RELEASE(startTime);
        
        completionHandler(jsonObject, webRequestError);
    }];
}



- (void)validateWithWebfingerForAuthority:(NSString *)authority
                      passiveAuthEndpoint:(NSString *)passiveAuthEndpoint
                                  context:(id<ADRequestContext>)context
                        completionHandler:(ADDiscoveryCallback)completionHandler
{
    NSUUID *correlationId = [context correlationId];
    
    // Construct webFingerURL
    NSURL *fullUrl = [NSURL URLWithString:passiveAuthEndpoint.lowercaseString];
    NSURL *webFingerURL = [NSURL URLWithString:
                           [NSString stringWithFormat:@"%@://%@/%@resource=%@", fullUrl.scheme, fullUrl.host, sWebFinger, authority]];
    
    AD_LOG_VERBOSE(@"WebFinger Request", correlationId, webFingerURL.absoluteString);
    
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:webFingerURL
                                                         context:context];
    
    [webRequest setIsGetRequest:YES];
    
    [[ADClientMetrics getInstance] addClientMetrics:webRequest.headers endpoint:webFingerURL.absoluteString];
    
    __block NSDate* startTime = [NSDate new];
    [webRequest send:^(NSError *error, ADWebResponse *webResponse) {
        ADAuthenticationError *adError = nil;
        
        if (error)
        {
            adError = [ADAuthenticationError errorFromNSError:error
                                                 errorDetails:error.localizedDescription
                                                correlationId:correlationId];
        }
        else
        {
            [self getJsonFromWebResponse:webResponse
                           correlationId:correlationId
                     acceptedStatusCodes:@[@200]
                                   error:&adError];
        }
        
        [[ADClientMetrics getInstance] endClientMetricsRecord:webFingerURL.absoluteString
                                                    startTime:startTime
                                                correlationId:correlationId
                                                 errorDetails:adError.localizedDescription];
        SAFE_ARC_RELEASE(startTime);
        
        completionHandler(!adError, adError);
    }];
}


- (NSString*)passiveEndpointFromDRSMetaData:(id)metaData
{
    return [[metaData objectForKey:@"IdentityProviderService"] objectForKey:@"PassiveAuthEndpoint"];
}


+ (NSString*)canonicalizeAuthority:(NSString *)authority
{
    if ([NSString adIsStringNilOrBlank:authority])
    {
        return nil;
    }
    
    NSString* trimmedAuthority = [[authority adTrimmedString] lowercaseString];
    NSURL* url = [NSURL URLWithString:trimmedAuthority];
    if (!url)
    {
        AD_LOG_WARN_F(@"The authority is not a valid URL", nil, @"Authority %@", authority);
        return nil;
    }
    NSString* scheme = url.scheme;
    if (![scheme isEqualToString:@"https"])
    {
        AD_LOG_WARN_F(@"Non HTTPS protocol for the authority", nil, @"Authority %@", authority);
        return nil;
    }
    
    url = url.absoluteURL;//Resolve any relative paths.
    NSArray* paths = url.pathComponents;//Returns '/' as the first and the tenant as the second element.
    if (paths.count < 2)
        return nil;//No path component: invalid URL
    
    NSString* tenant = [paths objectAtIndex:1];
    if ([NSString adIsStringNilOrBlank:tenant])
    {
        return nil;
    }
    
    NSString* host = url.host;
    if ([NSString adIsStringNilOrBlank:host])
    {
        return nil;
    }
    NSNumber* port = url.port;
    if (port)
    {
        trimmedAuthority = [NSString stringWithFormat:@"%@://%@:%d/%@", scheme, host, port.intValue, tenant];
    }
    else
    {
        trimmedAuthority = [NSString stringWithFormat:@"%@://%@/%@", scheme, host, tenant];
    }
    
    return trimmedAuthority;
}

@end

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
#import "ADAuthenticationResult.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
#import "NSDictionary+MSIDExtensions.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDBrokerResponse.h"
#import "MSIDLegacySingleResourceToken.h"
#import "ADTokenCacheItem+MSIDTokens.h"
#import "MSIDBrokerResponse+ADAL.h"
#import "MSIDAADV1Oauth2Factory.h"

@implementation ADAuthenticationResult (Internal)

- (id)initWithCancellation:(NSUUID*)correlationId
{
    ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation:correlationId];
    
    return [self initWithError:error status:AD_USER_CANCELLED correlationId:correlationId];
}

-(id) initWithItem: (ADTokenCacheItem*) item
multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
     correlationId: (NSUUID*) correlationId
{
    self = [super init];
    if (self)
    {
        // Non ObjC Objects
        _status = AD_SUCCEEDED;
        _multiResourceRefreshToken = multiResourceRefreshToken;
        
        // ObjC Objects
        _tokenCacheItem = item;
        _correlationId = correlationId;
        _authority = item.authority;
    }
    return self;
}

- (id)initWithError:(ADAuthenticationError *)error
             status:(ADAuthenticationResultStatus)status
      correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_ARGUMENT(error);
    
    self = [super init];
    if (self)
    {
        _status = status;
        _error = error;
        _correlationId = correlationId;
    }
    return self;
}

+ (ADAuthenticationResult*)resultFromTokenCacheItem:(ADTokenCacheItem *)item
                               multiResourceRefreshToken:(BOOL)multiResourceRefreshToken
                                           correlationId:(NSUUID *)correlationId
{
    if (!item)
    {
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult was created with nil token item."
                                                                        correlationId:correlationId];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithItem:item
                                                        multiResourceRefreshToken:multiResourceRefreshToken
                                                                    correlationId:correlationId];
    
    return result;
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
{
    return [self resultFromError:error correlationId:nil];
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
                             correlationId: (NSUUID*) correlationId
{
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithError:error
                                                                            status:AD_FAILED
                                                                     correlationId:correlationId];
    
    return result;
}

+ (ADAuthenticationResult *)resultFromMSIDError:(NSError *)error
{
    ADAuthenticationError *adError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:error];
    return [self resultFromError:adError];
}

+ (ADAuthenticationResult *)resultFromMSIDError:(NSError *)error
                                  correlationId:(NSUUID *)correlationId
{
    ADAuthenticationError *adError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:error];
    return [self resultFromError:adError correlationId:correlationId];
}

+ (ADAuthenticationResult*)resultFromParameterError:(NSString *)details
{
    return [self resultFromParameterError:details correlationId:nil];
}

+ (ADAuthenticationResult*)resultFromParameterError:(NSString *)details
                                      correlationId:(NSUUID*)correlationId
{
    ADAuthenticationError* adError = [ADAuthenticationError invalidArgumentError:details correlationId:correlationId];
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithError:adError
                                                                            status:AD_FAILED
                                                                     correlationId:correlationId];
    
    return result;
}

+ (ADAuthenticationResult*)resultFromCancellation
{
    return [self resultFromCancellation:nil];
}

+ (ADAuthenticationResult*)resultFromCancellation:(NSUUID *)correlationId
{
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithCancellation:correlationId];
    return result;
}

+ (ADAuthenticationResult*)resultForNoBrokerResponse
{
    NSError* nsError = [NSError errorWithDomain:ADBrokerResponseErrorDomain
                                           code:AD_ERROR_TOKENBROKER_UNKNOWN
                                       userInfo:nil];
    ADAuthenticationError* error = [ADAuthenticationError errorFromNSError:nsError
                                                              errorDetails: @"No broker response received."
                                                             correlationId:nil];
    return [ADAuthenticationResult resultFromError:error correlationId:nil];
}

+ (ADAuthenticationResult*)resultForBrokerErrorResponse:(NSDictionary*)response
{
    NSUUID* correlationId = nil;
    NSString* uuidString = [response valueForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE];
    if (uuidString)
    {
        correlationId = [[NSUUID alloc] initWithUUIDString:[response valueForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE]];
    }
    
    // Otherwise parse out the error condition
    ADAuthenticationError* error = nil;
    
    NSString* errorDetails = [response valueForKey:MSID_OAUTH2_ERROR_DESCRIPTION];
    if (!errorDetails)
    {
        errorDetails = @"Broker did not provide any details";
    }
        
    NSString* strErrorCode = [response valueForKey:@"error_code"];
    NSInteger errorCode = AD_ERROR_TOKENBROKER_UNKNOWN;
    if (strErrorCode && ![strErrorCode isEqualToString:@"0"])
    {
        errorCode = [strErrorCode integerValue];
    }
    
    NSString* protocolCode = [response valueForKey:@"protocol_code"];
    if (!protocolCode)
    {
        // Older brokers used to send the protocol code as "code" and the error code not at all
        protocolCode = [response valueForKey:@"code"];
    }
    
    // Create error object according to error_domain value.
    // Old version of broker won't send this value, we set it to ADAuthenticationErrorDomain like before
    NSString *errorDomain = [response valueForKey:@"error_domain"] ? [response valueForKey:@"error_domain"] : ADAuthenticationErrorDomain;
    
    // Extract headers if it is http error
    if ([errorDomain isEqualToString:ADHTTPErrorCodeDomain])
    {
        NSDictionary *httpHeaders = [NSDictionary msidURLFormDecode:[response valueForKey:@"http_headers"]];
        error = [ADAuthenticationError errorFromHTTPErrorCode:errorCode body:errorDetails headers:httpHeaders correlationId:correlationId];
    }
    else
    {
        error = [ADAuthenticationError errorWithDomain:errorDomain
                                                  code:errorCode
                                     protocolErrorCode:protocolCode
                                          errorDetails:errorDetails
                                         correlationId:correlationId];
    }
    
    return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
}

+ (ADAuthenticationResult*)resultFromBrokerResponse:(MSIDBrokerResponse *)response
{
    if (!response)
    {
        return [self resultForNoBrokerResponse];
    }
    
    if (response.errorDescription)
    {
        return [self resultForBrokerErrorResponse:response.formDictionary];
    }
    
    NSUUID *correlationId =  nil;
    NSString *correlationIdStr = response.correlationId;
    
    if (correlationIdStr)
    {
        correlationId = [[NSUUID alloc] initWithUUIDString:correlationIdStr];
    }
    
    NSError *msidError = nil;

    MSIDAADV1Oauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
    
    BOOL processResult = [factory verifyResponse:response.tokenResponse
                                fromRefreshToken:NO
                                         context:nil
                                           error:&msidError];
    
    if (!processResult)
    {
        return [ADAuthenticationResult resultFromMSIDError:msidError];
    }
    
    BOOL isMRRT = response.tokenResponse.isMultiResource;
    
    MSIDConfiguration *config = [[MSIDConfiguration alloc] initWithAuthority:[NSURL URLWithString:response.authority] redirectUri:nil clientId:response.clientId target:response.resource];
    
    MSIDLegacySingleResourceToken *resultToken = [factory legacyTokenFromResponse:response.tokenResponse
                                                                    configuration:config];
    
    ADTokenCacheItem *item = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:resultToken];
    
    if (response.isAccessTokenInvalid)
    {
        item.accessToken = nil;
    }
    
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithItem:item
                                                        multiResourceRefreshToken:isMRRT
                                                                    correlationId:correlationId];
    return result;
    
}

- (void)setExtendedLifeTimeToken:(BOOL)extendedLifeTimeToken;
{
    _extendedLifeTimeToken = extendedLifeTimeToken;
}

- (void)setCloudAuthority:(NSString *)cloudAuthority
{
    _authority = cloudAuthority;
}

@end

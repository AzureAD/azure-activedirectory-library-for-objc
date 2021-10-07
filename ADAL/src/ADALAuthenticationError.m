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
#import "ADALAuthenticationError.h"

NSString* const ADAuthenticationErrorDomain = @"ADAuthenticationErrorDomain";
NSString* const ADBrokerResponseErrorDomain = @"ADBrokerResponseErrorDomain";
NSString* const ADKeychainErrorDomain = @"ADKeychainErrorDomain";
NSString* const ADHTTPErrorCodeDomain = @"ADHTTPErrorCodeDomain";
NSString* const ADOAuthServerErrorDomain = @"ADOAuthServerErrorDomain";

NSString* const ADHTTPHeadersKey = @"ADHTTPHeadersKey";
NSString* const ADSuberrorKey = @"ADSuberrorKey";
NSString* const ADBrokerVersionKey = @"ADBrokerVersionKey";
NSString* const ADUserIdKey = @"ADUserIdKey";

NSString* const ADInvalidArgumentMessage = @"The argument '%@' is invalid. Value:%@";

NSString* const ADCancelError = @"The user has cancelled the authorization.";
NSString* const ADNonHttpsRedirectError = @"The server has redirected to a non-https url.";

@implementation ADALAuthenticationError

@synthesize errorDetails = _errorDetails;
@synthesize protocolCode = _protocolCode;

- (id)init
{
    //Should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDomain:(NSString *)domain
                code:(NSInteger)code
            userInfo:(NSDictionary *)dict
{
    (void)domain;
    (void)code;
    (void)dict;
    
    //Overrides the parent class and ensures that it throws. This one should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (NSString *)description
{
    NSString* superDescription = [super description];
    
    NSString* codeStr = [self getStringForErrorCode:self.code domain:self.domain];
    
    return [NSString stringWithFormat:@"Error with code: %@ Domain: %@ ProtocolCode:%@ Details:%@. Inner error details: %@",
            codeStr, self.domain, self.protocolCode, self.errorDetails, superDescription];
}

- (id)initInternalWithDomain:(NSString *)domain
                        code:(NSInteger)code
                protocolCode:(NSString *)protocolCode
                errorDetails:(NSString *)details
               correlationId:(NSUUID *)correlationId
                    userInfo:(NSDictionary *)userInfo
                       quiet:(BOOL)quiet
{
    if (!domain)
    {
        domain = @"ADAL";
    }
    
    if (!(self = [super initWithDomain:domain code:code userInfo:userInfo]))
    {
        // If we're getting nil back here we have bigger problems and the logging below is going to fail anyways.`
        return nil;
    }
    
    _errorDetails = details;
    _protocolCode = protocolCode;
    
    if (!quiet)
    {
        NSString* codeStr = [self getStringForErrorCode:code domain:domain];
        MSID_LOG_ERROR_CORR(correlationId, @"Error raised: (Domain: \"%@\" Code: %@ ProtocolCode: \"%@\"", domain, codeStr, protocolCode);
        MSID_LOG_ERROR_CORR_PII(correlationId, @"Error raised: (Domain: \"%@\" Code: %@ ProtocolCode: \"%@\". Error details: %@", domain, codeStr, protocolCode, details);
    }
    
    return self;
}

+ (ADALAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo
{
    id obj = [[self alloc] initInternalWithDomain:domain
                                             code:code
                                     protocolCode:protocolCode
                                     errorDetails:details
                                    correlationId:correlationId
                                         userInfo:userInfo
                                            quiet:NO];
    return obj;
}

+ (ADALAuthenticationError*)errorFromArgument:(id)argumentValue
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(argumentName);
    
    //Constructs the applicable message and return the error:
    NSString* errorMessage = [NSString stringWithFormat:ADInvalidArgumentMessage, argumentName, argumentValue];
    return [self errorWithDomainInternal:ADAuthenticationErrorDomain
                                    code:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:errorMessage
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(nullable NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADAuthenticationErrorDomain
                                    code:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:error.domain
                                    code:error.code
                       protocolErrorCode:nil
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:error.userInfo];
}

+ (ADALAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:domain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
                                  userInfo:(NSDictionary *)userInfo
{
    return [self errorWithDomainInternal:domain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:userInfo];
}

+ (ADALAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                              userInfo:(NSDictionary *)userInfo
                                         correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADAuthenticationErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:userInfo];
}

+ (ADALAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                         correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADAuthenticationErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails
{
    ADALAuthenticationError* error =
    [[ADALAuthenticationError alloc] initInternalWithDomain:ADAuthenticationErrorDomain
                                                     code:code
                                             protocolCode:protocolCode
                                             errorDetails:errorDetails
                                            correlationId:nil
                                                 userInfo:nil
                                                    quiet:YES];
    return error;
}

+ (ADALAuthenticationError*)unexpectedInternalError:(NSString*)errorDetails
                                    correlationId:(NSUUID *)correlationId
{
    return [self errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                 protocolCode:nil
                                 errorDetails:errorDetails
                                correlationId:correlationId];
}

+ (ADALAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId
{
    return [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_USER_CANCEL
                                                  protocolCode:nil
                                                  errorDetails:ADCancelError
                                                 correlationId:correlationId];
}

+ (ADALAuthenticationError*)errorFromNonHttpsRedirect:(NSUUID *)correlationId
{
    return [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_NON_HTTPS_REDIRECT
                                                  protocolCode:nil
                                                  errorDetails:ADNonHttpsRedirectError
                                                 correlationId:correlationId];
}

+ (ADALAuthenticationError *)keychainErrorFromOperation:(NSString *)operation
                                               status:(OSStatus)status
                                        correlationId:(NSUUID *)correlationId
{
    NSString* details = [NSString stringWithFormat:@"Keychain failed during \"%@\" operation", operation];
    
    return [self errorWithDomainInternal:ADKeychainErrorDomain
                                    code:status
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError *)errorFromHTTPErrorCode:(NSInteger)code
                                             body:(NSString *)body
                                          headers:(NSDictionary *)headers
                                    correlationId:(NSUUID *)correlationId
{
    NSDictionary *userInfo = headers ? @{ADHTTPHeadersKey : headers} : nil;
    
    return [self errorWithDomainInternal:ADHTTPErrorCodeDomain
                                    code:code
                       protocolErrorCode:nil
                            errorDetails:body
                           correlationId:correlationId
                                userInfo:userInfo];
}

+ (ADALAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADOAuthServerErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:description
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADALAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId
                                   userInfo:(NSDictionary *)userInfo
{
    return [self errorWithDomainInternal:ADOAuthServerErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:description
                           correlationId:correlationId
                                userInfo:userInfo];
}

+ (ADALAuthenticationError *)errorFromExistingError:(ADALAuthenticationError *)error
                                    correlationID:(NSUUID *) correlationId
                               additionalUserInfo:(NSDictionary *)userInfo
{
    NSMutableDictionary* newUserInfo = [error userInfo] ? [[error userInfo] mutableCopy] : [[NSMutableDictionary alloc] initWithCapacity:[userInfo count]];
    [newUserInfo addEntriesFromDictionary:userInfo];
    return [self errorWithDomainInternal:error.domain
                                    code:error.code
                       protocolErrorCode:error.protocolCode
                            errorDetails:error.errorDetails
                           correlationId:correlationId
                                userInfo:newUserInfo];
}

#if AD_BROKER
+ (ADALAuthenticationError *)errorFromExistingProtectionPolicyRequiredError:(ADALAuthenticationError *) error
                                                            correlationID:(NSUUID *) correlationId
                                                                    token:(ADALTokenCacheItem*) token
{
    NSDictionary *tokenDictionary = token ? @{@"ADMAMToken":token} : @{};
    return [ADALAuthenticationError errorFromExistingError:error
                                           correlationID:correlationId
                                      additionalUserInfo:tokenDictionary];
}
#endif

- (NSString*)getStringForErrorCode:(NSInteger)code
                            domain:(NSString *)domain
{
    //code is ADErrorCode enum if domain is one of following
    if ([domain isEqualToString:ADAuthenticationErrorDomain] ||
        [domain isEqualToString:ADBrokerResponseErrorDomain] ||
        [domain isEqualToString:ADOAuthServerErrorDomain])
    {
        return [self.class stringForADErrorCode:(ADErrorCode)code];
    }
    return [NSString stringWithFormat:@"%ld", (long)code];
}

#define AD_ERROR_CODE_ENUM_CASE(_enum) case _enum: return @#_enum;

+ (NSString*)stringForADErrorCode:(ADErrorCode)code
{
    switch (code)
    {
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SUCCEEDED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UNEXPECTED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_USER_INPUT_NEEDED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_WPJ_REQUIRED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_OAUTH);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_WRONG_USER);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_NON_HTTPS_REDIRECT);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_INVALID_ID_TOKEN);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_MISSING_AUTHENTICATE_HEADER);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_UNSUPPORTED_REQUEST);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_AUTHORIZATION_CODE);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_CACHE_MULTIPLE_USERS);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_CACHE_VERSION_MISMATCH);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_CACHE_BAD_FORMAT);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_CACHE_NO_REFRESH_TOKEN);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UI_USER_CANCEL);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_UI_NOT_ON_MAIN_THREAD);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_UNKNOWN);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY);
            AD_ERROR_CODE_ENUM_CASE(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED);
            default:
                return [NSString stringWithFormat:@"%ld", (long)code];
    }
}

@end

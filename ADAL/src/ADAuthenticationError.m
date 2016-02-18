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
#import "ADAuthenticationError.h"

NSString* const ADAuthenticationErrorDomain = @"ADAuthenticationErrorDomain";
NSString* const ADInvalidArgumentDomain = @"ADAuthenticationErrorDomain";
NSString* const ADUnauthorizedResponseErrorDomain = @"ADUnauthorizedResponseErrorDomain";
NSString* const ADBrokerResponseErrorDomain = @"ADBrokerResponseErrorDomain";

NSString* const ADInvalidArgumentMessage = @"The argument '%@' is invalid. Value:%@";

NSString* const ADCancelError = @"The user has cancelled the authorization.";
NSString* const ADNonHttpsRedirectError = @"The server has redirected to a non-https url.";

@implementation ADAuthenticationError

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
    
    return [NSString stringWithFormat:@"Error with code: %lu Domain: %@ ProtocolCode:%@ Details:%@. Inner error details: %@",
            (long)self.code, self.domain, self.protocolCode, self.errorDetails, superDescription];
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
    
    self = [super initWithDomain:domain code:code userInfo:userInfo];
    if (self)
    {
        _errorDetails = details;
        SAFE_ARC_RETAIN(_errorDetails);
        _protocolCode = protocolCode;
        SAFE_ARC_RETAIN(_protocolCode);
    }
    
    if (!quiet)
    {
        NSString* message = [NSString stringWithFormat:@"Error raised: (Domain: \"%@\" Code:%lu ProtocolCode: \"%@\" Details: \"%@\"", domain, (long)code, protocolCode, details];
        NSDictionary* logDict = nil;
        if (correlationId)
        {
            logDict = @{ @"error" : self,
                         @"correlationId" : correlationId };
        }
        else
        {
            logDict = @{ @"error" : self };
        }
        
        AD_LOG_ERROR_DICT(message, code, correlationId, logDict, nil);
    }
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_errorDetails);
    SAFE_ARC_RELEASE(_protocolCode);
    
    SAFE_ARC_SUPER_DEALLOC();
}

+ (ADAuthenticationError *)errorWithDomainInternal:(NSString *)domain
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
    SAFE_ARC_AUTORELEASE(obj);
    return obj;
}

+ (ADAuthenticationError*)errorFromArgument:(id)argumentValue
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(argumentName);
    
    //Constructs the applicable message and return the error:
    NSString* errorMessage = [NSString stringWithFormat:ADInvalidArgumentMessage, argumentName, argumentValue];
    return [self errorWithDomainInternal:ADInvalidArgumentDomain
                                    code:AD_ERROR_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:errorMessage
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(nullable NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADInvalidArgumentDomain
                                    code:AD_ERROR_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)errorFromUnauthorizedResponse:(NSInteger)responseCode
                                           errorDetails:(NSString *)errorDetails
                                          correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADUnauthorizedResponseErrorDomain
                                    code:responseCode
                       protocolErrorCode:nil
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)errorFromNSError:(NSError *)error
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

+ (ADAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
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

+ (ADAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails
{
    ADAuthenticationError* error =
    [[ADAuthenticationError alloc] initInternalWithDomain:ADAuthenticationErrorDomain
                                                     code:code
                                             protocolCode:protocolCode
                                             errorDetails:errorDetails
                                            correlationId:nil
                                                 userInfo:nil
                                                    quiet:YES];
    
    SAFE_ARC_AUTORELEASE(error);
    return error;
}

+ (ADAuthenticationError*)unexpectedInternalError:(NSString*)errorDetails
                                    correlationId:(NSUUID *)correlationId
{
    return [self errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                 protocolCode:nil
                                 errorDetails:errorDetails
                                correlationId:correlationId];
}

+ (ADAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId
{
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_CANCEL
                                                  protocolCode:nil
                                                  errorDetails:ADCancelError
                                                 correlationId:correlationId];
}

+ (ADAuthenticationError*)errorFromNonHttpsRedirect:(NSUUID *)correlationId
{
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_NON_HTTPS_REDIRECT
                                                  protocolCode:nil
                                                  errorDetails:ADNonHttpsRedirectError
                                                 correlationId:correlationId];
}


@end

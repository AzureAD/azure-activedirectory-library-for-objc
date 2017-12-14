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

#import "ADAuthenticationErrorConverter.h"
#import "ADAuthenticationError.h"
#import "MSIDError.h"

static NSDictionary *s_errorDomainMapping;
static NSDictionary *s_errorCodeMapping;

@interface ADAuthenticationError (ErrorConverterUtil)
+ (ADAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo;
@end

@implementation ADAuthenticationErrorConverter

+ (void)initialize
{
    s_errorDomainMapping = @{
                             MSIDErrorDomain : ADAuthenticationErrorDomain
                             };
    
    s_errorCodeMapping = @{
                           //sample format is like @"MSIDErrorDomain|-10000":@"-20000"
                           };
}

+ (ADAuthenticationError *)ADAuthenticationErrorFromMSIDError:(NSError *)msidError
{
    if (!msidError)
    {
        return nil;
    }
    
    //Map domain
    NSString *domain = msidError.domain;
    if (domain && s_errorDomainMapping[domain])
    {
        domain = s_errorDomainMapping[domain];
    }
    
    //Map errorCode. Note that errorCode must be mapped together with domain
    NSInteger errorCode = msidError.code;
    NSString *mapKey = [NSString stringWithFormat:@"%@|%ld", msidError.domain, (long)errorCode];
    NSString *mapValue = s_errorCodeMapping[mapKey];
    if (![NSString msidIsStringNilOrBlank:mapValue])
    {
        errorCode = [mapValue integerValue];
    }
    
    NSMutableDictionary *userInfo = nil;
    if (msidError.userInfo[NSUnderlyingErrorKey] || msidError.userInfo[MSIDHTTPHeadersKey])
    {
        userInfo = [NSMutableDictionary new];
        [userInfo setValue:msidError.userInfo[NSUnderlyingErrorKey] forKey:NSUnderlyingErrorKey];
        [userInfo setValue:msidError.userInfo[MSIDHTTPHeadersKey] forKey:ADHTTPHeadersKey];
    }
    
    return [ADAuthenticationError errorWithDomainInternal:domain
                                                     code:errorCode
                                        protocolErrorCode:msidError.userInfo[MSIDOAuthErrorKey]
                                             errorDetails:msidError.userInfo[MSIDErrorDescriptionKey]
                                            correlationId:msidError.userInfo[MSIDCorrelationIdKey]
                                                 userInfo:userInfo];
}

@end

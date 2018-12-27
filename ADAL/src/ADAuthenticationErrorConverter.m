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
#import "ADAuthenticationErrorMap.h"

@interface ADAuthenticationError (ErrorConverterUtil)
+ (ADAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo;
@end

@implementation ADAuthenticationErrorConverter

+ (ADAuthenticationError *)ADAuthenticationErrorFromMSIDError:(NSError *)msidError
{
    if (!msidError)
    {
        return nil;
    }
    
    // Map domain
    NSString *domain = [ADAuthenticationErrorMap adErrorDomainFromMsidError:msidError];
    
    // Map errorCode
    // errorCode mapping is needed only if domain is in s_errorCodeMapping
    NSInteger errorCode = [ADAuthenticationErrorMap adErrorCodeFromMsidError:msidError];
    
    NSMutableDictionary *userInfo = [NSMutableDictionary new];
    
    for (NSString *key in [msidError.userInfo allKeys])
    {
        NSString *mappedKey = [ADAuthenticationErrorMap userInfoKeys][key] ?: key;
        userInfo[mappedKey] = msidError.userInfo[key];
    }

    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:msidError.userInfo[MSIDCorrelationIdKey]];

    return [ADAuthenticationError errorWithDomainInternal:domain
                                                     code:errorCode
                                        protocolErrorCode:msidError.userInfo[MSIDOAuthErrorKey]
                                             errorDetails:msidError.userInfo[MSIDErrorDescriptionKey]
                                            correlationId:correlationId
                                                 userInfo:userInfo];
}

@end

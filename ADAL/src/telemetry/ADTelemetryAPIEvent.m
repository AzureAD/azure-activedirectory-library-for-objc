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

#import "ADTelemetryAPIEvent.h"

@implementation ADTelemetryAPIEvent

- (void)setResultStatus:(ADAuthenticationResultStatus)status
{
    NSString* statusStr = nil;
    switch (status) {
        case AD_SUCCEEDED:
            statusStr = @"SUCCEEDED";
            break;
        case AD_FAILED:
            statusStr = @"FAILED";
            break;
        case AD_USER_CANCELLED:
            statusStr = @"USER_CANCELLED";
            break;
        default:
            statusStr = @"UNKNOWN";
    }
    
    [self setProperty:@"status" value:statusStr];
}

- (void)setCorrelationId:(NSUUID*)correlationId
{
    [self setProperty:@"correlation_id" value:[correlationId UUIDString]];
}

- (void)setUserId:(NSString*)userId;
{
    [self setProperty:@"user_id" value:[userId adComputeSHA256]];
}

- (void)setClientId:(NSString*)clientId
{
    [self setProperty:@"client_id" value:clientId];
}

- (void)setIsExtendedLifeTimeToken:(NSString*)isExtendedLifeToken
{
    [self setProperty:@"is_extended_life_time_token" value:isExtendedLifeToken];
}

- (void)setErrorCode:(NSString*)errorCode
{
    [self setProperty:@"error_code" value:errorCode];
}

- (void)setProtocolCode:(NSString*)protocolCode
{
    [self setProperty:@"protocol_code" value:protocolCode];
}

- (void)setErrorDescription:(NSString*)errorDescription
{
    [self setProperty:@"error_description" value:errorDescription];
}

- (void)setErrorDomain:(NSString*)errorDomain
{
    [self setProperty:@"error_domain" value:errorDomain];
}

- (void)setAuthorityValidationStatus:(NSString*)status
{
    [self setProperty:@"validation_status" value:status];
}

- (void)setAuthority:(NSString*)authority
{
    [self setProperty:@"authority" value:authority];
}

- (void)setGrantType:(NSString*)grantType
{
    [self setProperty:@"grant_type" value:grantType];
}

- (void)setAPIStatus:(NSString*)status
{
    [self setProperty:@"api_status" value:status];
}

- (void)setAPIId:(NSString*)apiId
{
    [self setProperty:@"api_id" value:apiId];
}

@end
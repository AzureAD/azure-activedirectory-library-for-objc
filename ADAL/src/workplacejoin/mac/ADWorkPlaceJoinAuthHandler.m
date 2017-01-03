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

#import "ADWorkPlaceJoinAuthHandler.h"
#import "ADWorkPlaceJoinUtil.h"
#import "ADRegistrationInformation.h"


@implementation ADWorkPlaceJoinAuthHandler

+ (void)load
{
    [ADURLProtocol registerHandler:self authMethod:NSURLAuthenticationMethodClientCertificate];
}

+ (void)resetHandler
{
}

+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge*)challenge
             connection:(NSURLConnection*)connection
               protocol:(ADURLProtocol*)protocol
{
#pragma unused(connection)
    
    AD_LOG_INFO_F(@"Attempting to handle WPJ client challenge", protocol.correlationId, @"host: %@", challenge.protectionSpace.host);
    
    ADAuthenticationError* adError = nil;    
    ADRegistrationInformation *info = [ADWorkPlaceJoinUtil getRegistrationInformation:protocol.correlationId error:&adError];
    
    if (!info || ![info isWorkPlaceJoined])
    {
        AD_LOG_INFO_F(@"Device is not workplace joined.", protocol.correlationId, @"host: %@", challenge.protectionSpace.host);
        return NO;
    }
    
    NSURLCredential* creds = [NSURLCredential credentialWithIdentity:info.securityIdentity
                                                        certificates:[NSArray arrayWithObject:(__bridge id)info.certificate]
                                                         persistence:NSURLCredentialPersistenceNone];
    [[challenge sender] useCredential:creds forAuthenticationChallenge:challenge];
    
    return YES;
}

@end

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
#import "ADTokenCacheItem+Internal.h"
#import "ADAuthenticationError.h"
#import "ADUserInformation.h"
#import "ADUserInformation+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADAuthenticationResult+Internal.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADAuthorityUtils.h"
#import "MSIDClientInfo.h"

@implementation ADTokenCacheItem (Internal)

- (void)fillUserInformation:(NSString*)idToken clientInfo:(MSIDClientInfo *)clientInfo
{
    if (!idToken)
    {
        // If there's no id token we still continue onwards
        return;
    }
    
    ADUserInformation* info = [ADUserInformation userInformationWithIdToken:idToken
                                                              homeAccountId:clientInfo.accountIdentifier
                                                                      error:nil];
    
    self.userInformation = info;
}

- (void)logMessage:(NSString *)message
     correlationId:(NSString *)correlationId
              mrrt:(BOOL)isMRRT
{
    (void)isMRRT;
    
    NSUUID* correlationUUID = [[NSUUID alloc] initWithUUIDString:correlationId];
    
    [self logMessage:message
               level:MSIDLogLevelInfo
       correlationId:correlationUUID];
}

- (void)logMessage:(NSString*)message level:(MSIDLogLevel)level correlationId:(NSUUID*)correlationId
{
    NSString* tokenMessage = nil;
    
    if (_accessToken && _refreshToken)
    {
        tokenMessage = [NSString stringWithFormat:@"AT (%@) + RT (%@) Expires: %@", [_accessToken msidTokenHash], [_refreshToken msidTokenHash], _expiresOn];
    }
    else if (_accessToken)
    {
        tokenMessage = [NSString stringWithFormat:@"AT (%@) Expires: %@", [_accessToken msidTokenHash], _expiresOn];
    }
    else if (_refreshToken)
    {
        tokenMessage = [NSString stringWithFormat:@"RT (%@)", [_refreshToken msidTokenHash]];
    }
    else
    {
        tokenMessage = @"token";
    }
    
    if (message)
    {
        tokenMessage = [NSString stringWithFormat:@"%@ %@", message, tokenMessage];
    }
    
    [[MSIDLogger sharedLogger] logLevel:level
                                context:nil
                          correlationId:correlationId
                                  isPII:NO
                                 format:@"%@ {\n\tresource = %@\n\tclientId = %@\n\tauthority = %@\n\tuserId = %@\n}",
     tokenMessage, _resource, _clientId, _authority, _userInformation.userId];
}

- (NSString *)speInfo
{
    return [_additionalServer objectForKey:MSID_TELEMETRY_KEY_SPE_INFO];
}

@end

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

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }
#define THIRTY_DAYS_IN_SECONDS (30*24*60*60)

- (void)checkCorrelationId:(NSDictionary*)response
      requestCorrelationId:(NSUUID*)requestCorrelationId
{
    MSID_LOG_VERBOSE_CORR(requestCorrelationId, @"Token extraction. Attempt to extract the data from the server response.");
    
    NSString* responseId = [response objectForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE];
    if (![NSString msidIsStringNilOrBlank:responseId])
    {
        NSUUID* responseUUID = [[NSUUID alloc] initWithUUIDString:responseId];
        if (!responseUUID)
        {
            MSID_LOG_INFO_CORR(requestCorrelationId, @"Bad correlation id - The received correlation id is not a valid UUID. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
        else if (![requestCorrelationId isEqual:responseUUID])
        {
            MSID_LOG_INFO_CORR(requestCorrelationId, @"Correlation id mismatch - Mismatch between the sent correlation id and the received one. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
    }
    else
    {
        MSID_LOG_INFO_CORR(requestCorrelationId, @"Missing correlation id - No correlation id received for request with correlation id: %@", [requestCorrelationId UUIDString]);
    }
}

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                fromRefreshToken:(ADTokenCacheItem *)refreshToken
                            requestCorrelationId:(NSUUID*)requestCorrelationId
{
    return [self processTokenResponse:response
                     fromRefreshToken:refreshToken
                 requestCorrelationId:requestCorrelationId
                         fieldToCheck:MSID_OAUTH2_ACCESS_TOKEN];
}

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                fromRefreshToken:(ADTokenCacheItem *)refreshToken
                            requestCorrelationId:(NSUUID*)requestCorrelationId
                                    fieldToCheck:(NSString*)fieldToCheck
{
    if (!response)
    {
        ADAuthenticationError *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                                              protocolCode:nil
                                                                              errorDetails:@"processTokenResponse called without a response dictionary"
                                                                             correlationId:requestCorrelationId];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    [self checkCorrelationId:response requestCorrelationId:requestCorrelationId];
    
    ADAuthenticationError *error = [ADAuthenticationContext errorFromDictionary:response errorCode:(refreshToken) ? AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED : AD_ERROR_SERVER_OAUTH];
    if (error)
    {
        if (refreshToken)
        {
            NSMutableDictionary *userInfo = [error userInfo] ? [[error userInfo] mutableCopy] : [[NSMutableDictionary alloc] initWithCapacity:1];
            if (refreshToken.userInformation.userId)
            {
                [userInfo setObject:refreshToken.userInformation.userId forKey:ADUserIdKey];
            }
            error = [ADAuthenticationError errorFromExistingError:error
                                                    correlationID:requestCorrelationId
                                               additionalUserInfo:userInfo];
        }
        return [ADAuthenticationResult resultFromError:error];
    }
    
    NSString *value = [response objectForKey:fieldToCheck];
    if (![NSString msidIsStringNilOrBlank:value])
    {
        BOOL isMrrt = [self fillItemWithResponse:response];
        return [ADAuthenticationResult resultFromTokenCacheItem:self
                                           multiResourceRefreshToken:isMrrt
                                                       correlationId:requestCorrelationId];
    }
    else
    {
        // Bad item, the field we're looking for is missing.
        NSString *details = [NSString stringWithFormat:@"Authentication response received without expected \"%@\"", fieldToCheck];
        ADAuthenticationError *error = [ADAuthenticationError unexpectedInternalError:details correlationId:requestCorrelationId];
        return [ADAuthenticationResult resultFromError:error];
    }
}

- (void)fillUserInformation:(NSString*)idToken clientInfo:(MSIDClientInfo *)clientInfo
{
    if (!idToken)
    {
        // If there's no id token we still continue onwards
        return;
    }
    
    ADUserInformation* info = [ADUserInformation userInformationWithIdToken:idToken
                                                                 homeUserId:clientInfo.userIdentifier
                                                                      error:nil];
    
    self.userInformation = info;
}

- (void)fillExpiration:(NSMutableDictionary*)responseDictionary
{
    id expires_in = [responseDictionary objectForKey:@"expires_in"];
    id expires_on = [responseDictionary objectForKey:@"expires_on"];
    [responseDictionary removeObjectForKey:@"expires_in"];
    [responseDictionary removeObjectForKey:@"expires_on"];
    
    
    NSDate *expires    = nil;
    
    if (expires_in && [expires_in respondsToSelector:@selector(doubleValue)])
    {
        expires = [NSDate dateWithTimeIntervalSinceNow:[expires_in doubleValue]];
    }
    else if (expires_on && [expires_on respondsToSelector:@selector(doubleValue)])
    {
        expires = [NSDate dateWithTimeIntervalSince1970:[expires_on doubleValue]];
    }
    else if (expires_in || expires_on)
    {
        MSID_LOG_WARN(nil, @"Unparsable time - The response value for the access token expiration cannot be parsed: %@", expires);
    }
    else
    {
        MSID_LOG_WARN(nil, @"The server did not return the expiration time for the access token.");
    }
    
    if (!expires)
    {
        expires = [NSDate dateWithTimeIntervalSinceNow:3600.0]; //Assume 1hr expiration
    }
    
    _expiresOn = expires;
    
    // convert ext_expires_in to ext_expires_on
    id extendedExpiresIn = [responseDictionary valueForKey:@"ext_expires_in"];
    [responseDictionary removeObjectForKey:@"ext_expires_in"];
    
    if (extendedExpiresIn && [extendedExpiresIn respondsToSelector:@selector(doubleValue)])
    {
        [responseDictionary setObject:[NSDate dateWithTimeIntervalSinceNow:[extendedExpiresIn doubleValue]]
                                 forKey:@"ext_expires_on"];
    }
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


#define FILL_FIELD(_FIELD, _KEY, _CLASS) \
{ \
    id _val = [responseDictionary valueForKey:_KEY]; \
    if (_val && [_val isKindOfClass:_CLASS]) \
    { \
        self._FIELD = _val; \
    } \
    [responseDictionary removeObjectForKey:_KEY]; \
}

- (BOOL)fillItemWithResponse:(NSDictionary*)response
{
    if (!response)
    {
        return NO;
    }
    
    NSMutableDictionary* responseDictionary = [response mutableCopy];
    
    BOOL isMRRT = ![NSString msidIsStringNilOrBlank:[responseDictionary objectForKey:MSID_OAUTH2_RESOURCE]] && ![NSString msidIsStringNilOrBlank:[responseDictionary objectForKey:MSID_OAUTH2_REFRESH_TOKEN]];
    
    MSIDClientInfo *clientInfo = [[MSIDClientInfo alloc] initWithRawClientInfo:[responseDictionary valueForKey:MSID_OAUTH2_CLIENT_INFO] error:nil];
    
    [self fillUserInformation:[responseDictionary valueForKey:MSID_OAUTH2_ID_TOKEN] clientInfo:clientInfo];
    [responseDictionary removeObjectForKey:MSID_OAUTH2_ID_TOKEN];
    
    FILL_FIELD(authority, MSID_OAUTH2_AUTHORITY, [NSString class]);
    FILL_FIELD(resource, MSID_OAUTH2_RESOURCE, [NSString class]);
    FILL_FIELD(clientId, MSID_OAUTH2_CLIENT_ID, [NSString class]);
    FILL_FIELD(accessToken, MSID_OAUTH2_ACCESS_TOKEN, [NSString class]);
    FILL_FIELD(refreshToken, MSID_OAUTH2_REFRESH_TOKEN, [NSString class]);
    FILL_FIELD(accessTokenType, MSID_OAUTH2_TOKEN_TYPE, [NSString class]);
    FILL_FIELD(familyId, ADAL_CLIENT_FAMILY_ID, [NSString class]);
    
    [self fillExpiration:responseDictionary];
    
    [self logMessage:@"Received"
       correlationId:[responseDictionary objectForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE]
                mrrt:isMRRT];
    
    // Store what we haven't cached to _additionalServer
    _additionalServer = responseDictionary;
    
    return isMRRT;
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

- (BOOL)isExtendedLifetimeValid
{
    NSDate* extendedExpiresOn = [_additionalServer valueForKey:@"ext_expires_on"];
    
    //extended lifetime is only valid if it contains an access token
    if (extendedExpiresOn && ![NSString msidIsStringNilOrBlank:_accessToken])
    {
        return [extendedExpiresOn compare:[NSDate date]] == NSOrderedDescending;
    }
    
    return NO;
}

- (NSString *)speInfo
{
    return [_additionalServer objectForKey:MSID_TELEMETRY_KEY_SPE_INFO];
}

@end

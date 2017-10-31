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
#import "ADOAuth2Constants.h"
#import "ADUserInformation.h"
#import "ADLogger+Internal.h"
#import "NSString+ADHelperMethods.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTelemetryEventStrings.h"

@implementation ADTokenCacheItem (Internal)

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }
#define THIRTY_DAYS_IN_SECONDS (30*24*60*60)

- (void)checkCorrelationId:(NSDictionary*)response
      requestCorrelationId:(NSUUID*)requestCorrelationId
{
    AD_LOG_VERBOSE(requestCorrelationId, NO, @"Token extraction. Attempt to extract the data from the server response.");
    
    NSString* responseId = [response objectForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    if (![NSString adIsStringNilOrBlank:responseId])
    {
        NSUUID* responseUUID = [[NSUUID alloc] initWithUUIDString:responseId];
        if (!responseUUID)
        {
            AD_LOG_INFO(requestCorrelationId, NO, @"Bad correlation id - The received correlation id is not a valid UUID. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
        else if (![requestCorrelationId isEqual:responseUUID])
        {
            AD_LOG_INFO(requestCorrelationId, NO, @"Correlation id mismatch - Mismatch between the sent correlation id and the received one. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
    }
    else
    {
        AD_LOG_INFO(requestCorrelationId, NO, @"Missing correlation id - No correlation id received for request with correlation id: %@", [requestCorrelationId UUIDString]);
    }
}

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                     fromRefresh:(BOOL)fromRefreshTokenWorkflow
                            requestCorrelationId:(NSUUID*)requestCorrelationId
{
    return [self processTokenResponse:response
                          fromRefresh:fromRefreshTokenWorkflow
                 requestCorrelationId:requestCorrelationId
                         fieldToCheck:OAUTH2_ACCESS_TOKEN];
}

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                     fromRefresh:(BOOL)fromRefreshTokenWorkflow
                            requestCorrelationId:(NSUUID*)requestCorrelationId
                                    fieldToCheck:(NSString*)fieldToCheck
{
    if (!response)
    {
        ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                                              protocolCode:nil
                                                                              errorDetails:@"processTokenResponse called without a response dictionary"
                                                                             correlationId:requestCorrelationId];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    [self checkCorrelationId:response requestCorrelationId:requestCorrelationId];
    
    ADAuthenticationError* error = [ADAuthenticationContext errorFromDictionary:response errorCode:(fromRefreshTokenWorkflow) ? AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED : AD_ERROR_SERVER_OAUTH];
    if (error)
    {
        return [ADAuthenticationResult resultFromError:error];
    }
    
    NSString* value = [response objectForKey:fieldToCheck];
    if (![NSString adIsStringNilOrBlank:value])
    {
        BOOL isMrrt = [self fillItemWithResponse:response];
        return [ADAuthenticationResult resultFromTokenCacheItem:self
                                           multiResourceRefreshToken:isMrrt
                                                       correlationId:requestCorrelationId];
    }
    else
    {
        // Bad item, the field we're looking for is missing.
        NSString* details = [NSString stringWithFormat:@"Authentication response received without expected \"%@\"", fieldToCheck];
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:details correlationId:requestCorrelationId];
        return [ADAuthenticationResult resultFromError:error];
    }
}

- (void)fillUserInformation:(NSString*)idToken
{
    if (!idToken)
    {
        // If there's no id token we still continue onwards
        return;
    }
    
    ADUserInformation* info = nil;
    info = [ADUserInformation userInformationWithIdToken:idToken
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
        AD_LOG_WARN(nil, NO, @"Unparsable time - The response value for the access token expiration cannot be parsed: %@", expires);
    }
    else
    {
        AD_LOG_WARN(nil, NO, @"The server did not return the expiration time for the access token.");
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
               level:ADAL_LOG_LEVEL_INFO
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
    
    BOOL isMRRT = ![NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_RESOURCE]] && ![NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_REFRESH_TOKEN]];
    
    [self fillUserInformation:[responseDictionary valueForKey:OAUTH2_ID_TOKEN]];
    [responseDictionary removeObjectForKey:OAUTH2_ID_TOKEN];
    
    FILL_FIELD(authority, OAUTH2_AUTHORITY, [NSString class]);
    FILL_FIELD(resource, OAUTH2_RESOURCE, [NSString class]);
    FILL_FIELD(clientId, OAUTH2_CLIENT_ID, [NSString class]);
    FILL_FIELD(accessToken, OAUTH2_ACCESS_TOKEN, [NSString class]);
    FILL_FIELD(refreshToken, OAUTH2_REFRESH_TOKEN, [NSString class]);
    FILL_FIELD(accessTokenType, OAUTH2_TOKEN_TYPE, [NSString class]);
    FILL_FIELD(familyId, ADAL_CLIENT_FAMILY_ID, [NSString class]);
    
    [self fillExpiration:responseDictionary];
    
    [self logMessage:@"Received"
       correlationId:[responseDictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE]
                mrrt:isMRRT];
    
    // Store what we haven't cached to _additionalServer
    _additionalServer = responseDictionary;
    
    return isMRRT;
}

- (void)makeTombstone:(NSDictionary *)tombstoneEntries
{
    NSMutableDictionary* tombstoneDictionary = [NSMutableDictionary new];
    
    //avoid bundleId being nil, as it will be stored in a NSMutableDictionary
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier];
    
    if (bundleId)
    {
        [tombstoneDictionary setObject:bundleId forKey:@"bundleId"];
    }
    
    if (tombstoneEntries)
    {
        [tombstoneDictionary addEntriesFromDictionary:tombstoneEntries];
    }
    
    //wipe out the refresh token
    _refreshToken = @"<tombstone>";
    _tombstone = tombstoneDictionary;
    _expiresOn = [NSDate dateWithTimeIntervalSinceNow:THIRTY_DAYS_IN_SECONDS];//tombstones should be removed after 30 days
}

- (void)logMessage:(NSString*)message level:(ADAL_LOG_LEVEL)level correlationId:(NSUUID*)correlationId
{
    if (_tombstone)
    {
        [ADLogger log:level context:self correlationId:correlationId isPii:YES
               format:@"%@", _tombstone];
        [ADLogger log:level context:self correlationId:correlationId isPii:NO
               format:@"{\n\tresource: %@\n\tclientId: %@\n\tauthority:%@\n}", _resource, _clientId, _authority];
        
        return;
    }
    
    NSString* tokenMessage = nil;
    
    if (_accessToken && _refreshToken)
    {
        tokenMessage = [NSString stringWithFormat:@"AT (%@) + RT (%@) Expires: %@", [ADLogger getHash:_accessToken], [ADLogger getHash:_refreshToken], _expiresOn];
    }
    else if (_accessToken)
    {
        tokenMessage = [NSString stringWithFormat:@"AT (%@) Expires: %@", [ADLogger getHash:_accessToken], _expiresOn];
    }
    else if (_refreshToken)
    {
        tokenMessage = [NSString stringWithFormat:@"RT (%@)", [ADLogger getHash:_refreshToken]];
    }
    else
    {
        tokenMessage = @"token";
    }
    
    if (message)
    {
        tokenMessage = [NSString stringWithFormat:@"%@ %@", message, tokenMessage];
    }
    
    [ADLogger log:level context:self correlationId:correlationId isPii:YES
           format:@"%@ {\n\tresource = %@\n\tclientId = %@\n\tauthority = %@\n\tuserId = %@\n}",
     tokenMessage, _resource, _clientId, _authority, _userInformation.userId];
}

- (BOOL)isExtendedLifetimeValid
{
    NSDate* extendedExpiresOn = [_additionalServer valueForKey:@"ext_expires_on"];
    
    //extended lifetime is only valid if it contains an access token
    if (extendedExpiresOn && ![NSString adIsStringNilOrBlank:_accessToken])
    {
        return [extendedExpiresOn compare:[NSDate date]] == NSOrderedDescending;
    }
    
    return NO;
}

- (NSString *)speInfo
{
    return [_additionalServer objectForKey:AD_TELEMETRY_KEY_SPE_INFO];
}

@end

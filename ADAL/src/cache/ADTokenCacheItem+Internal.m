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

@implementation ADTokenCacheItem (Internal)

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }

- (void)checkCorrelationId:(NSDictionary*)response
      requestCorrelationId:(NSUUID*)requestCorrelationId
{
    AD_LOG_VERBOSE(@"Token extraction", requestCorrelationId, @"Attempt to extract the data from the server response.");
    
    NSString* responseId = [response objectForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    if (![NSString adIsStringNilOrBlank:responseId])
    {
        NSUUID* responseUUID = [[NSUUID alloc] initWithUUIDString:responseId];
        if (!responseUUID)
        {
            AD_LOG_INFO_F(@"Bad correlation id", nil, @"The received correlation id is not a valid UUID. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
        else if (![requestCorrelationId isEqual:responseUUID])
        {
            AD_LOG_INFO_F(@"Correlation id mismatch", nil, @"Mismatch between the sent correlation id and the received one. Sent: %@; Received: %@", requestCorrelationId, responseId);
        }
        SAFE_ARC_RELEASE(responseUUID);
    }
    else
    {
        AD_LOG_INFO_F(@"Missing correlation id", nil, @"No correlation id received for request with correlation id: %@", [requestCorrelationId UUIDString]);
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
        ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                              protocolCode:@"adal cachce"
                                                                              errorDetails:@"processTokenResponse called without a response dictionary"
                                                                             correlationId:requestCorrelationId];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    [self checkCorrelationId:response requestCorrelationId:requestCorrelationId];
    
    ADAuthenticationError* error = [ADAuthenticationContext errorFromDictionary:response errorCode:(fromRefreshTokenWorkflow) ? AD_ERROR_INVALID_REFRESH_TOKEN : AD_ERROR_AUTHENTICATION];
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

- (void)fillExpiration:(NSDictionary*)responseDictionary
{
    id expires_in = [responseDictionary objectForKey:@"expires_in"];
    id expires_on = [responseDictionary objectForKey:@"expires_on"];
    
    
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
        AD_LOG_WARN_F(@"Unparsable time", nil, @"The response value for the access token expiration cannot be parsed: %@", expires);
    }
    else
    {
        AD_LOG_WARN(@"Missing expiration time.", nil, @"The server did not return the expiration time for the access token.");
    }
    
    if (!expires)
    {
        expires = [NSDate dateWithTimeIntervalSinceNow:3600.0]; //Assume 1hr expiration
    }
    self.expiresOn = expires;
}

- (void)logWithCorrelationId:(NSString*)correlationId
                        mrrt:(BOOL)isMRRT
{
    (void)isMRRT;
    
    NSUUID* correlationUUID = [[NSUUID alloc] initWithUUIDString:correlationId];
    
    [self logMessage:nil
               level:ADAL_LOG_LEVEL_VERBOSE
       correlationId:correlationUUID];
    
    SAFE_ARC_RELEASE(correlationUUID);
}


#define FILL_FIELD(_FIELD, _KEY) { id _val = [responseDictionary valueForKey:_KEY]; if (_val) { self._FIELD = _val; } }

- (BOOL)fillItemWithResponse:(NSDictionary*)responseDictionary
{
    if (!responseDictionary)
    {
        return NO;
    }
    
    [self fillUserInformation:[responseDictionary valueForKey:OAUTH2_ID_TOKEN]];
    
    FILL_FIELD(authority, OAUTH2_AUTHORITY);
    FILL_FIELD(resource, OAUTH2_RESOURCE);
    FILL_FIELD(clientId, OAUTH2_CLIENT_ID);
    FILL_FIELD(accessToken, OAUTH2_ACCESS_TOKEN);
    FILL_FIELD(refreshToken, OAUTH2_REFRESH_TOKEN);
    FILL_FIELD(accessTokenType, OAUTH2_TOKEN_TYPE);
    FILL_FIELD(familyId, ADAL_CLIENT_FAMILY_ID);
    
    [self fillExpiration:responseDictionary];
    
    BOOL isMRRT = ![NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_RESOURCE]] && ![NSString adIsStringNilOrBlank:self.refreshToken];
    
    [self logWithCorrelationId:[responseDictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE] mrrt:isMRRT];
    
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

}

- (void)logMessage:(NSString*)message level:(ADAL_LOG_LEVEL)level correlationId:(NSUUID*)correlationId
{
    if (_tombstone)
    {
        NSString* tombstoneMessage = nil;
        if (message)
        {
            tombstoneMessage = [NSString stringWithFormat:@"%@ tombstone : %@", message, _tombstone];
        }
        else
        {
            tombstoneMessage = [NSString stringWithFormat:@"Tombstone : %@", _tombstone];
        }
        
        [ADLogger log:level
              message:tombstoneMessage
            errorCode:0
        correlationId:correlationId
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
    
    [ADLogger log:level
          message:tokenMessage
        errorCode:0
    correlationId:correlationId
           format:@"{\n\tresource = %@\n\tclientId = %@\n\tauthority = %@\n\tuserId = %@\n}",
     _resource, _clientId, _authority, _userInformation.userId];
}


@end

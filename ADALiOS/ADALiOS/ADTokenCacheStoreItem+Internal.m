// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADAL.h"
#import "ADTokenCacheStoreItem+Internal.h"
#import "ADAuthenticationError.h"
#import "ADOAuth2Constants.h"
#import "ADProfileInfo.h"
#import "ADLogger.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheStoreItem (Internal)

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }

- (void)fillExpiration:(NSDictionary*)responseDictionary
{
    id expires_in = [responseDictionary objectForKey:OAUTH2_EXPIRES_IN];
    
    //if access_token was NOT returned then ONLY use id_token_expires_in
    if ([NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_ACCESS_TOKEN]])
    {
        expires_in = [responseDictionary objectForKey:OAUTH2_ID_TOKEN_EXPIRES_IN];
    }
    
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
        AD_LOG_WARN(@"Missing expiration time.", @"The server did not return the expiration time for the access token.");
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
    NSUUID* correlationUUID = [[NSUUID alloc] initWithUUIDString:correlationId];
    if (self.token)
    {
        [ADLogger logToken:self.token
                 tokenType:self.tokenType
                 expiresOn:self.expiresOn
             correlationId:correlationUUID];
    }
    
    if (self.refreshToken)
    {
        [ADLogger logToken:self.refreshToken
                 tokenType:isMRRT ? @"multi-resource refresh token" : @"refresh token"
                 expiresOn:nil
             correlationId:correlationUUID];
    }
}


#define FILL_FIELD(_FIELD, _KEY) { id _val = [responseDictionary valueForKey:_KEY]; if (_val) { self._FIELD = _val; } }

- (BOOL)fillItemWithResponse:(NSDictionary*)responseDictionary
{
    if (!responseDictionary)
    {
        return NO;
    }
    
    self.profileInfo = [ADProfileInfo profileInfoWithEncodedString:[responseDictionary objectForKey:OAUTH2_PROFILE_INFO]
                                                             error:nil];
    
    //if access token was returned (is NOT nil or blank) then get scopes from the response.
    if (![NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_ACCESS_TOKEN]])
    {
        NSArray* scopes = [[responseDictionary objectForKey:OAUTH2_SCOPE] componentsSeparatedByString:@" "];
        self.scopes = [NSSet setWithArray:scopes];
        FILL_FIELD(token, OAUTH2_ACCESS_TOKEN);
    }
    else
    {
        //if NO access token is present then use client id as a scope
        self.scopes = [NSSet setWithObject:self.clientId];
        FILL_FIELD(token, OAUTH2_ID_TOKEN);
    }
    
    FILL_FIELD(authority, OAUTH2_AUTHORITY);
    FILL_FIELD(clientId, OAUTH2_CLIENT_ID);
    FILL_FIELD(refreshToken, OAUTH2_REFRESH_TOKEN);
    FILL_FIELD(tokenType, OAUTH2_TOKEN_TYPE);
    
    [self fillExpiration:responseDictionary];
    
    BOOL isMRRT = ![NSString adIsStringNilOrBlank:self.refreshToken];
    
    [self logWithCorrelationId:[responseDictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE] mrrt:isMRRT];
    
    return isMRRT;
}


@end

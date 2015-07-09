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
#import "ADUserInformation.h"
#import "ADLogger.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheStoreItem (Internal)

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }

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
    id expires_in = [responseDictionary objectForKey:@"expires_on"];
    if (!expires_in)
    {
        expires_in = [responseDictionary objectForKey:@"expires_in"];
    }
    
    NSDate *expires    = nil;
    
    if (expires_in)
    {
        if ( [expires_in isKindOfClass:[NSString class]] )
        {
            NSNumberFormatter *formatter = [[NSNumberFormatter alloc] init];
            
            expires = [NSDate dateWithTimeIntervalSinceNow:[formatter numberFromString:expires_in].longValue];
        }
        else if ( [expires_in isKindOfClass:[NSNumber class]] )
        {
            expires = [NSDate dateWithTimeIntervalSinceNow:((NSNumber *)expires_in).longValue];
        }
        else
        {
            AD_LOG_WARN_F(@"Unparsable time", @"The response value for the access token expiration cannot be parsed: %@", expires);
            // Unparseable, use default value
            expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//1 hour
        }
    }
    else
    {
        AD_LOG_WARN(@"Missing expiration time.", @"The server did not return the expiration time for the access token.");
        expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//Assume 1hr expiration
    }
    
    self.expiresOn = expires;
}

- (void)logWithCorrelationId:(NSString*)correlationId
                        mrrt:(BOOL)isMRRT
{
    NSUUID* correlationUUID = [[NSUUID alloc] initWithUUIDString:correlationId];
    if (self.accessToken)
    {
        [ADLogger logToken:self.accessToken
                 tokenType:self.accessTokenType
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
    
    [self fillUserInformation:[responseDictionary valueForKey:OAUTH2_ID_TOKEN]];
    
    FILL_FIELD(authority, OAUTH2_AUTHORITY);
    FILL_FIELD(resource, OAUTH2_RESOURCE);
    FILL_FIELD(clientId, OAUTH2_CLIENT_ID);
    FILL_FIELD(accessToken, OAUTH2_ACCESS_TOKEN);
    FILL_FIELD(refreshToken, OAUTH2_REFRESH_TOKEN);
    FILL_FIELD(accessTokenType, OAUTH2_TOKEN_TYPE);
    
    [self fillExpiration:responseDictionary];
    
    BOOL isMRRT = ![NSString adIsStringNilOrBlank:[responseDictionary objectForKey:OAUTH2_RESOURCE]] && ![NSString adIsStringNilOrBlank:self.refreshToken];
    
    [self logWithCorrelationId:[responseDictionary objectForKey:OAUTH2_CORRELATION_ID_RESPONSE] mrrt:isMRRT];
    
    return isMRRT;
}


@end

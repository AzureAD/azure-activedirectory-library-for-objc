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

@implementation ADTokenCacheStoreItem (Internal)

#define CHECK_ERROR(_CHECK, _ERR) { if (_CHECK) { if (error) {*error = _ERR;} return; } }

- (void)fillUserInformation:(NSString*)idToken
                      error:(ADAuthenticationError* __autoreleasing *)error
{
    if (!idToken)
    {
        return;
    }
    
    ADUserInformation* info = nil;
    ADAuthenticationError* adError = nil;
    info = [ADUserInformation userInformationWithIdToken:idToken
                                                   error:&adError];
    
    CHECK_ERROR(adError, adError);
    
    self.userInformation = info;
}

#define FILL_FIELD(_FIELD, _KEY) { id _val = [responseDictionary valueForKey:_KEY]; if (_val) { self._FIELD = _val; } }

- (void)fillItemWithResponse:(NSDictionary*)responseDictionary
                       error:(ADAuthenticationError* __autoreleasing *)error
{
    ADAuthenticationError* adError = nil;
    CHECK_ERROR(!responseDictionary, [ADAuthenticationError errorFromArgument:responseDictionary
                                                                 argumentName:@"responseDictionary"]);
    
    if (self.userInformation == nil)
    {
        [self fillUserInformation:[responseDictionary valueForKey:OAUTH2_ID_TOKEN]
                            error:&adError];
        
        if (error)
        {
            *error = adError;
        }
    }
    
    FILL_FIELD(authority, OAUTH2_AUTHORITY);
    FILL_FIELD(resource, OAUTH2_RESOURCE);
    FILL_FIELD(clientId, OAUTH2_CLIENT_ID);
    FILL_FIELD(accessToken, OAUTH2_ACCESS_TOKEN);
    FILL_FIELD(refreshToken, OAUTH2_REFRESH_TOKEN);
    FILL_FIELD(accessTokenType, OAUTH2_TOKEN_TYPE);
    
    // Token response
    id expires_in = [responseDictionary objectForKey:@"expires_on"];
    NSDate *expires    = nil;
    
    if ( expires_in != nil )
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

- (void)logWithCorrelationId:(NSUUID*)correlationId
{
    if (self.accessToken)
    {
        [ADLogger logToken:self.accessToken
                 tokenType:self.accessTokenType
                 expiresOn:self.expiresOn
             correlationId:correlationId];
    }
    
    if (self.refreshToken)
    {
        [ADLogger logToken:self.refreshToken
                 tokenType:self.multiResourceRefreshToken ? @"multi-resource refresh token" : @"refresh token"
                 expiresOn:nil
             correlationId:correlationId];
    }
}


@end

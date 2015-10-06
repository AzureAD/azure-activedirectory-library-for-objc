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
#import "ADAuthenticationResult.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheStoreItem.h"
#import "ADOAuth2Constants.h"
#import "ADUserInformation.h"

@implementation ADAuthenticationResult (Internal)

-(id) initWithCancellation
{
    ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation];
    
    return [self initWithError:error status:AD_USER_CANCELLED];
}

-(id) initWithItem: (ADTokenCacheStoreItem*) item
multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
{
    self = [super init];
    if (self)
    {
        _status                    = AD_SUCCEEDED;
        _error                     = nil;
        _tokenCacheStoreItem       = SAFE_ARC_RETAIN(item);
        _multiResourceRefreshToken = multiResourceRefreshToken;
    }
    return self;
}

-(id) initWithError: (ADAuthenticationError*)error
             status: (ADAuthenticationResultStatus) status
{
    THROW_ON_NIL_ARGUMENT(error);
    
    self = [super init];
    if (self)
    {
        _status = status;
        _error  = SAFE_ARC_RETAIN(error);
    }
    return self;
}

/*! Creates an instance of the result from the cache store. */
+(ADAuthenticationResult*) resultFromTokenCacheStoreItem: (ADTokenCacheStoreItem*) item
                               multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
{
    if (item)
    {
        ADAuthenticationError* error = nil;
        [item extractKeyWithError:&error];
        if (error)
        {
            //Bad item, return error:
            return [ADAuthenticationResult resultFromError:error];
        }
        if ([NSString adIsStringNilOrBlank:item.accessToken])
        {
            //Bad item, the access token should be accurate, else an error should be
            //reported instead of this creator:
            ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from item with no access token."];
            return [ADAuthenticationResult resultFromError:error];
        }
        //The item can be used, just use it:
        return SAFE_ARC_AUTORELEASE([[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:multiResourceRefreshToken]);
    }
    else
    {
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from nil token item."];
        return [ADAuthenticationResult resultFromError:error];
    }
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
{
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc]initWithError:error status:AD_FAILED] ;
    return SAFE_ARC_AUTORELEASE(result);
}

+(ADAuthenticationResult*) resultFromCancellation
{
    ADAuthenticationResult* result = [[ADAuthenticationResult alloc] initWithCancellation];
    return SAFE_ARC_AUTORELEASE(result);
}

 +(ADAuthenticationResult*)resultFromBrokerResponse:(NSDictionary*)response
{
    ADAuthenticationResult* result = nil;
    ADTokenCacheStoreItem* item = nil;
    
    if(!response || [response valueForKey:OAUTH2_ERROR_DESCRIPTION])
    {
        ADAuthenticationError* error = nil;
        NSString* errorDetails = nil;
        NSInteger errorCode = 0;
        if (response)
        {
            errorDetails = [response valueForKey:OAUTH2_ERROR_DESCRIPTION];
            errorCode = [[response valueForKey:@"error_code"] integerValue];
            
            if (!errorDetails)
            {
                errorDetails = @"Broker did not provide any details";
            }
        }
        else
        {
            errorDetails = @"No broker response received.";
        }
        
        error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:ADBrokerResponseErrorDomain code:errorCode userInfo:nil] errorDetails:errorDetails];
        
        return [ADAuthenticationResult resultFromError:error];
    }
    
    ADUserInformation* info = nil;
    if([response valueForKey:OAUTH2_ID_TOKEN])
    {
        ADAuthenticationError* error = nil;
        info = [ADUserInformation userInformationWithIdToken:[response valueForKey:OAUTH2_ID_TOKEN] error:&error];
        if (error)
        {
            return [ADAuthenticationResult resultFromError:error];
        }
    }
    
    item = [ADTokenCacheStoreItem new];
    item.userInformation = info;
    item.authority =  [response valueForKey:OAUTH2_AUTHORITY];
    item.resource = [response valueForKey:OAUTH2_RESOURCE];
    item.clientId = [response valueForKey:OAUTH2_CLIENT_ID];
    item.accessToken = [response valueForKey:OAUTH2_ACCESS_TOKEN];
    item.refreshToken = [response valueForKey:OAUTH2_REFRESH_TOKEN];
    
    item.accessTokenType = @"Bearer";
    // Token response
    id expires_in = [response objectForKey:@"expires_on"];
    NSDate *expires    = nil;
    
    if ( expires_in != nil )
    {
        if ( [expires_in respondsToSelector:@selector(doubleValue)] )
        {
            expires = [NSDate dateWithTimeIntervalSince1970:[expires_in doubleValue]];
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
    
    item.expiresOn = expires;
    
    
    BOOL isMRRT = item.resource && item.refreshToken;

    result = [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:isMRRT];
    SAFE_ARC_AUTORELEASE(result);
    SAFE_ARC_RELEASE(item);
    return result;
}

@end

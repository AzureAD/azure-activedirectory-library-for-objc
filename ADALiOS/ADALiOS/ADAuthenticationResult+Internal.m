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


#import "ADALiOS.h"
#import "ADAuthenticationResult.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheStoreItem+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADUserInformation.h"

@implementation ADAuthenticationResult (Internal)

-(id) initWithCancellation: (NSUUID*) correlationId
{
    ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation];
    
    return [self initWithError:error status:AD_USER_CANCELLED correlationId:correlationId];
}

-(id) initWithItem: (ADTokenCacheStoreItem*) item
multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
     correlationId: (NSUUID*) correlationId
{
    self = [super init];
    if (self)
    {
        _status = AD_SUCCEEDED;
        _tokenCacheStoreItem = item;
        _multiResourceRefreshToken = multiResourceRefreshToken;
        _correlationId = correlationId;
    }
    return self;
}

-(id) initWithError: (ADAuthenticationError*)error
             status: (ADAuthenticationResultStatus) status
      correlationId: (NSUUID*) correlationId
{
    THROW_ON_NIL_ARGUMENT(error);
    
    self = [super init];
    if (self)
    {
        _status = status;
        _error = error;
        _correlationId = correlationId;
    }
    return self;
}

/*! Creates an instance of the result from the cache store. */
+(ADAuthenticationResult*) resultFromTokenCacheStoreItem: (ADTokenCacheStoreItem*) item
                               multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
{
    return [self resultFromTokenCacheStoreItem:item multiResourceRefreshToken:multiResourceRefreshToken correlationId:nil];
}

+(ADAuthenticationResult*) resultFromTokenCacheStoreItem: (ADTokenCacheStoreItem*) item
                               multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
                                           correlationId: (NSUUID*) correlationId
{
    if (item)
    {
        ADAuthenticationError* error;
        [item extractKeyWithError:&error];
        if (error)
        {
            //Bad item, return error:
            return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
        if ([NSString adIsStringNilOrBlank:item.accessToken])
        {
            //Bad item, the access token should be accurate, else an error should be
            //reported instead of this creator:
            ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from item with no access token."];
            return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
        //The item can be used, just use it:
        return [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:multiResourceRefreshToken correlationId:correlationId];
    }
    else
    {
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from nil token item."];
        return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
    }
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
{
    return [self resultFromError:error correlationId:nil];
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
                             correlationId: (NSUUID*) correlationId
{
    ADAuthenticationResult* result = [ADAuthenticationResult alloc];
    return [result initWithError:error status:AD_FAILED correlationId:correlationId];
}

+ (ADAuthenticationResult*)resultFromParameterError:(NSString *)details
{
    return [self resultFromParameterError:details correlationId:nil];
}

+ (ADAuthenticationResult*)resultFromParameterError:(NSString *)details
                                      correlationId: (NSUUID*) correlationId
{
    return [[ADAuthenticationResult alloc] initWithError:[ADAuthenticationError invalidArgumentError:details] status:AD_FAILED correlationId:correlationId];
}

+(ADAuthenticationResult*) resultFromCancellation
{
    return [self resultFromCancellation:nil];
}

+(ADAuthenticationResult*) resultFromCancellation: (NSUUID*) correlationId
{
    ADAuthenticationResult* result = [ADAuthenticationResult alloc];
    return [result initWithCancellation:correlationId];
}

+(ADAuthenticationResult*) resultFromBrokerResponse: (NSDictionary*) response
{
    ADTokenCacheStoreItem* item = nil;
    
    NSUUID* correlationId = [response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE] ?
                            [[NSUUID alloc] initWithUUIDString:[response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]]
                            : nil;
    
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
        
        return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
    }
    
    item = [ADTokenCacheStoreItem new];
    [item setAccessTokenType:@"Bearer"];
    BOOL isMRRT = [item fillItemWithResponse:response];
    return [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:isMRRT correlationId:correlationId];
}

@end

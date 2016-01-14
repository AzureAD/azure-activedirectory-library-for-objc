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

+ (ADAuthenticationResult*)resultFromTokenCacheStoreItem:(ADTokenCacheStoreItem *)item
                               multiResourceRefreshToken:(BOOL)multiResourceRefreshToken
                                           correlationId:(NSUUID *)correlationId
{
    if (!item)
    {
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from nil token item."];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    return [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:multiResourceRefreshToken correlationId:correlationId];
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

+ (ADAuthenticationResult*)resultForNoBrokerResponse
{
    NSError* nsError = [NSError errorWithDomain:ADBrokerResponseErrorDomain
                                           code:AD_ERROR_BROKER_UNKNOWN
                                       userInfo:nil];
    ADAuthenticationError* error = [ADAuthenticationError errorFromNSError:nsError
                                                              errorDetails: @"No broker response received."];
    return [ADAuthenticationResult resultFromError:error correlationId:nil];
}

+ (ADAuthenticationResult*)resultForBrokerErrorResponse:(NSDictionary*)response
{
    NSString* correlationIdStr = [response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    NSUUID* correlationId =  correlationIdStr ? [[NSUUID alloc] initWithUUIDString:correlationIdStr] : nil;
    
    // Otherwise parse out the error condition
    ADAuthenticationError* error = nil;
    
    NSString* errorDetails = [response valueForKey:OAUTH2_ERROR_DESCRIPTION];
    if (!errorDetails)
    {
        errorDetails = @"Broker did not provide any details";
    }
        
    NSString* strErrorCode = [response valueForKey:@"error_code"];
    NSInteger errorCode = AD_ERROR_BROKER_UNKNOWN;
    if (strErrorCode && ![strErrorCode isEqualToString:@"0"])
    {
        errorCode = [strErrorCode integerValue];
    }
    
    NSString* protocolCode = [response valueForKey:@"protocol_code"];
    if (!protocolCode)
    {
        // Older brokers used to send the protocol code as "code" and the error code not at all
        protocolCode = [response valueForKey:@"code"];
    }
    
    if (![NSString adIsStringNilOrBlank:protocolCode])
    {
       
        error = [ADAuthenticationError errorFromAuthenticationError:errorCode
                                                       protocolCode:protocolCode
                                                       errorDetails:errorDetails];
    }
    else
    {
        NSError* nsError = [NSError errorWithDomain:ADBrokerResponseErrorDomain
                                               code:errorCode
                                           userInfo:nil];
        error = [ADAuthenticationError errorFromNSError:nsError errorDetails:errorDetails];
    }
    
    return [ADAuthenticationResult resultFromError:error correlationId:correlationId];

}

+ (ADAuthenticationResult *)resultFromBrokerResponse:(NSDictionary *)response
{
    if (!response)
    {
        return [self resultForNoBrokerResponse];
    }
    
    if ([response valueForKey:OAUTH2_ERROR_DESCRIPTION])
    {
        return [self resultForBrokerErrorResponse:response];
    }
    
    NSUUID* correlationId =  nil;
    NSString* correlationIdStr = [response valueForKey:OAUTH2_CORRELATION_ID_RESPONSE];
    if (correlationIdStr)
    {
        correlationId = [[NSUUID alloc] initWithUUIDString:correlationIdStr];
    }

    ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
    [item setAccessTokenType:@"Bearer"];
    [item setMarkAsDead:NO];
    BOOL isMRRT = [item fillItemWithResponse:response];
    return [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:isMRRT correlationId:correlationId];
    
}

@end

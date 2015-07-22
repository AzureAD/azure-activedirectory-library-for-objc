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

#import "ADTestAuthenticationContext.h"
#import "../ADALiOS/ADALiOS.h"
#import "../ADALiOS/ADOAuth2Constants.h"
#import "../ADALiOS/ADAuthenticationRequest.h"
#import "../ADALiOS/ADAuthenticationResult+Internal.h"

@interface ADTestAuthenticationRequest : ADAuthenticationRequest

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
               completion:( void (^)(NSDictionary *) )completionBlock;

@end

@implementation ADTestAuthenticationContext

- (ADTestAuthenticationContext*)initWithAuthority:(NSString*)authority
                                validateAuthority:(BOOL)validateAuthority
                                  tokenCacheStore:(id<ADTokenCacheStoring>)tokenCache
                                            error:(ADAuthenticationError* __autoreleasing *)error
{
    if (!(self = [super initWithAuthority:authority
                        validateAuthority:validateAuthority
                           tokenCacheStore:tokenCache
                                    error:error]))
    {
        return nil;
    }
    
    _expectedRequests = [NSMutableArray new];
    _responses = [NSMutableArray new];
    
    return self;
}

- (void)queueExpectedRequest:(NSDictionary*)expectedRequest
                    response:(NSDictionary*)response
{
    [_expectedRequests addObject:expectedRequest];
    [_responses addObject:response];
}

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
               completion:( void (^)(NSDictionary *) )completionBlock
{
    ++mNumRequests;
    
    if ([_expectedRequests count] == 0 || [_responses count] == 0)
    {
        _errorMessage = @"Missing expected request and response!";
        completionBlock(nil);
        return;
    }
    
    NSDictionary* expectedRequest = [_expectedRequests firstObject];
    [_expectedRequests removeObjectAtIndex:0];
    
    NSDictionary* response = [_responses firstObject];
    [_responses removeObjectAtIndex:0];
    
    if (!requestCorrelationId)
    {
        _errorMessage = @"Missing request correlation id.";
        completionBlock(response);
        return;
    }
    if (!request_data || !request_data.count)
    {
       _errorMessage = @"Nil or empty request send to the server.";
        completionBlock(response);
        return;
    }
    
//    NSString* state;
//    if (1 == mNumRequests)
//    {
//        mCorrelationId1 = requestCorrelationId;
//        state = mRequestedState1 = [request_data objectForKey:OAUTH2_STATE];
//    }
//    else
//    {
//        mCorrelationId2 = requestCorrelationId;
//        state = mRequestedState2 = [request_data objectForKey:OAUTH2_STATE];
//    }
    
    
    //Verify the data sent to the server:
    //The expected list will be modified in the loop below
    __block NSMutableArray* missingHeaders = [NSMutableArray new];
    
    [expectedRequest enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop)
    {
        NSString* expected = (NSString*)obj;
        NSString* result = [request_data objectForKey:key];
        if (!result)
        {
            [missingHeaders addObject:key];
            return;
        }
        
        if (![result isKindOfClass:[NSString class]])
        {
            _errorMessage = [NSString stringWithFormat:@"%@ in request_data is not a NSString! (actual: %@)", key, NSStringFromClass([result class])];
            *stop = YES;
            return;
        }
        
        // We pass empty string, when the value is not known, but the key is expected
        if (expected.length == 0 && result.length > 0)
        {
            return;
        }
        
        // Scopes are a set, and the order does not matter, so rebuild them into a set before comparing
        if ([key isEqualToString:@"scope"])
        {
            NSSet* expectedSet = [NSSet setWithArray:[[expected adUrlFormDecode] componentsSeparatedByString:@" "]];
            NSSet* actualSet = [NSSet setWithArray:[[result adUrlFormDecode] componentsSeparatedByString:@" "]];
            
            if (![expectedSet isEqualToSet:actualSet])
            {
                _errorMessage = [NSString stringWithFormat:@"Mismatch scopes, expected: (%@) actual: (%@)", expectedSet, actualSet];
                *stop = YES;
                return;
            }
        }
        else if (![expected isEqualToString:result])
        {
            if ([key isEqualToString:@"scope"])
            {
                _errorMessage = [NSString stringWithFormat:@"Requested data: Unexpected value for the key (%@): Expected: '%@'; Actual: '%@'", key, expected, result];
                *stop = YES;
                return;
            }
        }
        
    }];
    
    if (_errorMessage)
    {
        completionBlock(response);
        return;
    }
    
    if (missingHeaders.count)
    {
        //Some of the expected value were not present in the request:
        _errorMessage = [NSString stringWithFormat:@"Request data: Missing expected headers: %@", missingHeaders];
        completionBlock(response);
        return;
    }

    //If everything is ok, pass over the desired response:
    completionBlock(response);
}

- (ADAuthenticationRequest*)requestWithRedirectString:(NSString*)redirectUri
                                             clientId:(NSString*)clientId
                                      completionBlock:(ADAuthenticationCallback)completionBlock

{
    ADAuthenticationError* error = nil;
    
    ADAuthenticationRequest* request = [ADTestAuthenticationRequest requestWithContext:self
                                                                           redirectUri:redirectUri
                                                                              clientId:clientId
                                                                                 error:&error];
    
    if (!request)
    {
        completionBlock([ADAuthenticationResult resultFromError:error]);
    }
    
    return request;
}

- (NSString*)errorMessage
{
    return _errorMessage;
}

@end

@implementation ADTestAuthenticationRequest

//Override of the parent's request to allow testing of the class behavior.
- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [(ADTestAuthenticationContext*)_context requestWithServer:authorizationServer
                                                  requestData:request_data
                                         requestCorrelationId:_correlationId
                                              handledPkeyAuth:isHandlingPKeyAuthChallenge
                                            additionalHeaders:additionalHeaders
                                                   completion:completionBlock];
}


@end

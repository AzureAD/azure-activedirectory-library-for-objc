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

#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"

#import "ADAuthenticationContext+Internal.h"
#import "ADAuthenticationRequest.h"
#import "ADAuthenticationSettings.h"
#import "ADBrokerHelper.h"
#import "ADHelpers.h"
#import "ADPkeyAuthHelper.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserIdentifier.h"
#import "ADUserInformation.h"
#import "ADWebAuthController+Internal.h"

#if TARGET_OS_IPHONE
#import "ADBrokerKeyHelper.h"
#import "ADBrokerNotificationManager.h"
#endif // TARGET_OS_IPHONE

@implementation ADAuthenticationRequest (Broker)

+ (BOOL)respondsToUrl:(NSString*)url
{
    NSArray* urlTypes = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
    
    NSString* scheme = [[NSURL URLWithString:url] scheme];
    if (!scheme)
    {
        return NO;
    }
    
    for (NSDictionary* urlRole in urlTypes)
    {
        NSArray* urlSchemes = [urlRole objectForKey:@"CFBundleURLSchemes"];
        if ([urlSchemes containsObject:scheme])
        {
            return YES;
        }
    }
    
    return NO;
}

+ (void)internalHandleBrokerResponse:(NSURL *)response
{
    ADAuthenticationCallback completionBlock = [ADBrokerHelper copyAndClearCompletionBlock];
    HANDLE_ARGUMENT(response);
    
    NSString *qp = [response query];
    //expect to either response or error and description, AND correlation_id AND hash.
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    ADAuthenticationResult* result;
    
    if([queryParamsMap valueForKey:OAUTH2_ERROR_DESCRIPTION]){
        result = [ADAuthenticationResult resultFromBrokerResponse:queryParamsMap];
    }
    else
    {
        // Encrypting the broker response should not be a requirement on Mac as there shouldn't be a possibility of the response
        // accidentally going to the wrong app
#if TARGET_OS_IPHONE
        HANDLE_ARGUMENT([queryParamsMap valueForKey:BROKER_HASH_KEY]);
        
        NSString* hash = [queryParamsMap valueForKey:BROKER_HASH_KEY];
        NSString* encryptedBase64Response = [queryParamsMap valueForKey:BROKER_RESPONSE_KEY];
        NSString* msgVer = [queryParamsMap valueForKey:BROKER_MESSAGE_VERSION];
        NSInteger protocolVersion = 1;
        
        NSUUID* correlationId = [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE] ?
        [[NSUUID alloc] initWithUUIDString:[queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]]
        : nil;
        
        if (msgVer)
        {
            protocolVersion = [msgVer integerValue];
        }
        
        //decrypt response first
        ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
        ADAuthenticationError* error;
        NSData *encryptedResponse = [NSString Base64DecodeData:encryptedBase64Response ];
        NSData* decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse
                                                        version:protocolVersion
                                                          error:&error];
        NSString* decryptedString = nil;
        
        if(!error)
        {
            decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
            //now compute the hash on the unencrypted data
            if([NSString adSame:hash toString:[ADPkeyAuthHelper computeThumbprint:decrypted isSha2:YES]]){
                //create response from the decrypted payload
                queryParamsMap = [NSDictionary adURLFormDecode:decryptedString];
                [ADHelpers removeNullStringFrom:queryParamsMap];
                result = [ADAuthenticationResult resultFromBrokerResponse:queryParamsMap];
                
            }
            else
            {
                result = [ADAuthenticationResult resultFromError:[ADAuthenticationError errorFromNSError:[NSError errorWithDomain:ADAuthenticationErrorDomain
                                                                                                                             code:AD_ERROR_BROKER_RESPONSE_HASH_MISMATCH
                                                                                                                         userInfo:nil]
                                                                                            errorDetails:@"Decrypted response does not match the hash"]
                                                    correlationId:correlationId];
            }
        }
        else
        {
            result = [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
#else // !TARGET_OS_IPHONE
        // TODO: Broker support on Mac.
        result = [ADAuthenticationResult resultFromBrokerResponse:queryParamsMap];
#endif // TARGET_OS_IPHONE
    }
    
    if (AD_SUCCEEDED == result.status)
    {
        ADAuthenticationContext* ctx = [ADAuthenticationContext
                                        authenticationContextWithAuthority:result.tokenCacheItem.authority
                                        error:nil];
        
        [ctx updateCacheToResult:result
                       cacheItem:nil
                withRefreshToken:nil
            requestCorrelationId:nil];
        
        NSString* userId = [[[result tokenCacheItem] userInformation] userId];
        [ADAuthenticationContext updateResult:result
                   toUser:[ADUserIdentifier identifierWithId:userId]];
    }
    if (!completionBlock)
    {
        AD_LOG_ERROR(@"Received broker response without a completionBlock.", AD_FAILED, nil, nil);
#if TARGET_OS_IPHONE
        [ADWebAuthController setInterruptedBrokerResult:result];
#endif // TARGET_OS_IPHONE
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidReceieveResponseFromBroker
                                                        object:nil
                                                      userInfo:@{ @"response" : result }];
    
    
    if (completionBlock)
    {
        completionBlock(result);
    }
}

- (BOOL)canUseBroker
{
    return _context.credentialsType == AD_CREDENTIALS_AUTO && _context.validateAuthority == YES && [ADBrokerHelper canUseBroker];
}

- (void)callBroker:(ADAuthenticationCallback)completionBlock
{
    CHECK_FOR_NIL(_context.authority);
    CHECK_FOR_NIL(_resource);
    CHECK_FOR_NIL(_clientId);
    CHECK_FOR_NIL(_correlationId);
    
    ADAuthenticationError* error = nil;
    if(![ADAuthenticationRequest respondsToUrl:_redirectUri])
    {
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_REDIRECT_URI
                                                       protocolCode:nil
                                                       errorDetails:ADRedirectUriInvalidError];
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
        return;
    }
    
    AD_LOG_INFO(@"Invoking broker for authentication", _correlationId, nil);
#if TARGET_OS_IPHONE // Broker Message Encryption
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
    NSData* key = [brokerHelper getBrokerKey:&error];
    NSString* base64Key = [NSString Base64EncodeData:key];
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    CHECK_FOR_NIL(base64UrlKey);
#endif // TARGET_OS_IPHONE Broker Message Encryption
    
    NSString* adalVersion = [ADLogger getAdalVersion];
    CHECK_FOR_NIL(adalVersion);
    
    NSDictionary* queryDictionary = @{
                                      @"authority": _context.authority,
                                      @"resource" : _resource,
                                      @"client_id": _clientId,
                                      @"redirect_uri": _redirectUri,
                                      @"username_type": _identifier ? [_identifier typeAsString] : @"",
                                      @"username": _identifier.userId ? _identifier.userId : @"",
                                      @"force" : _promptBehavior == AD_FORCE_PROMPT ? @"YES" : @"NO",
                                      @"correlation_id": _correlationId,
#if TARGET_OS_IPHONE // Broker Message Encryption
                                      @"broker_key": base64UrlKey,
#endif // TARGET_OS_IPHONE Broker Message Encryption
                                      @"client_version": adalVersion,
									  BROKER_MAX_PROTOCOL_VERSION : @"2",
                                      @"extra_qp": _queryParams ? _queryParams : @"",
                                      };
    
    [ADBrokerHelper invokeBroker:queryDictionary completionHandler:completionBlock];
}

- (void)handleBrokerFromWebiewResponse:(NSString*)urlString
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    CHECK_FOR_NIL(_resource);
    
    ADAuthenticationError* error = nil;
    if(![ADAuthenticationRequest respondsToUrl:_redirectUri])
    {
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_REDIRECT_URI
                                                       protocolCode:nil
                                                       errorDetails:ADRedirectUriInvalidError];
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
        return;
    }
    
#if TARGET_OS_IPHONE // Broker Message Encryption
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
    NSData* key = [brokerHelper getBrokerKey:&error];
    NSString* base64Key = [NSString Base64EncodeData:key];
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    CHECK_FOR_NIL(base64UrlKey);
#endif // TARGET_OS_IPHONE Broker Message Encryption
    
    NSString* adalVersion = [ADLogger getAdalVersion];
    NSString* correlationIdStr = [_correlationId UUIDString];
    NSString* authority = _context.authority;
    
    CHECK_FOR_NIL(adalVersion);
    CHECK_FOR_NIL(authority);
    
    NSString* query = [[NSURL URLWithString:urlString] query];
    NSMutableDictionary* urlParams = [[NSDictionary adURLFormDecode:query] mutableCopy];
    
    [urlParams addEntriesFromDictionary:@{@"authority": _context.authority,
                                          @"resource" : _resource,
                                          @"client_id": _clientId,
                                          @"redirect_uri": _redirectUri,
                                          @"username_type": _identifier ? [_identifier typeAsString] : @"",
                                          @"username": _identifier.userId ? _identifier.userId : @"",
                                          @"correlation_id": correlationIdStr,
#if TARGET_OS_IPHONE // Broker Message Encryption
                                          @"broker_key": base64UrlKey,
#endif // TARGET_OS_IPHONE Broker Message Encryption
                                          @"client_version": adalVersion,
                                          @"extra_qp": _queryParams ? _queryParams : @"",
                                          }];
    
    if ([ADBrokerHelper canUseBroker])
    {
        [ADBrokerHelper invokeBroker:urlParams completionHandler:completionBlock];
    }
    else
    {
        [ADBrokerHelper promptBrokerInstall:urlParams completionHandler:completionBlock];
    }
}

@end

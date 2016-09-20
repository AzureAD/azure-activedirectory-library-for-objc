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
#import "ADAuthenticationResult.h"

#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#import "ADBrokerKeyHelper.h"
#import "ADBrokerNotificationManager.h"
#endif // TARGET_OS_IPHONE

NSString* kAdalResumeDictionaryKey = @"adal-broker-resume-dictionary";

@implementation ADAuthenticationRequest (Broker)

+ (BOOL)validBrokerRedirectUri:(NSString*)url
{
    NSArray* urlTypes = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
    
    NSURL* redirectURI = [NSURL URLWithString:url];
    
    NSString* scheme = redirectURI.scheme;
    if (!scheme)
    {
        return NO;
    }
    
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier];
    NSString* host = [redirectURI host];
    if (![host isEqualToString:bundleId])
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

+ (BOOL)internalHandleBrokerResponse:(NSURL *)response
{
#if TARGET_OS_IPHONE
    __block ADAuthenticationCallback completionBlock = [ADBrokerHelper copyAndClearCompletionBlock];
        
    ADAuthenticationResult* result = [self processBrokerResponse:response];
    
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kAdalResumeDictionaryKey];
    // If we didn't get an authentication result then assume it wasn't actually a broker
    // message. This allows the message to pass through to other handlers
    if (!result)
    {
        if (completionBlock)
        {
            // If we had a completion block, but didn't get a result from processBrokerResponse
            // we still need to hit the completion block to make sure there isn't any UI sitting
            // waiting on a response that won't come.
            ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_NOT_A_BROKER_RESPONSE
                                                                                    protocolCode:nil
                                                                                    errorDetails:@"Application received a URL that was not a broker response"
                                                                                   correlationId:nil];
            ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:adError];
            completionBlock(result);
        }
        return NO;
    }
    
    if (completionBlock)
    {
        completionBlock(result);
    }
    else
    {
        AD_LOG_ERROR(@"Received broker response without a completionBlock.", AD_FAILED, nil, nil);
        
        // TODO: Add this result to cache as well
        [ADWebAuthController setInterruptedBrokerResult:result];
    }
    
    return YES;
#else
    (void)response;
    return NO;
#endif // TARGET_OS_IPHONE
}

+ (ADAuthenticationResult *)processBrokerResponse:(NSURL *)response
{
#if TARGET_OS_IPHONE

    if (!response)
    {
        return nil;
    }
    
    NSDictionary* resumeDictionary = [[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey];
    if (!resumeDictionary)
    {
        return nil;
    }
    
    NSString* redirectUri = [resumeDictionary objectForKey:@"redirect_uri"];
    if (!redirectUri)
    {
        return nil;
    }
    
    // Check to make sure this response is coming from the redirect URI we're expecting.
    if (![[[response absoluteString] lowercaseString] hasPrefix:[redirectUri lowercaseString]])
    {
        return nil;
    }
    
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
        NSString* hash = [queryParamsMap valueForKey:BROKER_HASH_KEY];
        if (!hash)
        {
            return nil;
        }
        
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
        ADAuthenticationError* error = nil;
        NSData *encryptedResponse = [NSString Base64DecodeData:encryptedBase64Response ];
        NSData* decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse
                                                        version:protocolVersion
                                                          error:&error];
        if (!decrypted)
        {
            return [ADAuthenticationResult resultFromError:error];
        }
        
        
        NSString* decryptedString = nil;
        
        if(!error)
        {
            decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
            //now compute the hash on the unencrypted data
            NSString* actualHash = [ADPkeyAuthHelper computeThumbprint:decrypted isSha2:YES];
            if([NSString adSame:hash toString:actualHash])
            {
                //create response from the decrypted payload
                queryParamsMap = [NSDictionary adURLFormDecode:decryptedString];
                [ADHelpers removeNullStringFrom:queryParamsMap];
                result = [ADAuthenticationResult resultFromBrokerResponse:queryParamsMap];
                
            }
            else
            {
                NSError* nsErr = [NSError errorWithDomain:ADAuthenticationErrorDomain
                                                     code:AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH
                                                 userInfo:nil];
                ADAuthenticationError* adErr = [ADAuthenticationError errorFromNSError:nsErr
                                                                          errorDetails:@"Decrypted response does not match the hash"
                                                                         correlationId:correlationId];

                result = [ADAuthenticationResult resultFromError:adErr];
            }
        }
        else
        {
            result = [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
    }
    
    if (AD_SUCCEEDED == result.status)
    {
        ADTokenCacheAccessor* cache = [[ADTokenCacheAccessor alloc] initWithDataSource:[ADKeychainTokenCache defaultKeychainCache]
                                                                             authority:result.tokenCacheItem.authority];
        
        [cache updateCacheToResult:result cacheItem:nil refreshToken:nil correlationId:nil];
        
        NSString* userId = [[[result tokenCacheItem] userInformation] userId];
        [ADAuthenticationContext updateResult:result
                   toUser:[ADUserIdentifier identifierWithId:userId]];
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidReceieveResponseFromBroker
                                                        object:nil
                                                      userInfo:@{ @"response" : result }];
    return result;
#else
    (void)response;
    return nil;
#endif
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
    if(![ADAuthenticationRequest validBrokerRedirectUri:_redirectUri])
    {
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI
                                                       protocolCode:nil
                                                       errorDetails:ADRedirectUriInvalidError
                                                      correlationId:_correlationId];
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
        return;
    }
    
    AD_LOG_INFO(@"Invoking broker for authentication", _correlationId, nil);
#if TARGET_OS_IPHONE // Broker Message Encryption
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
    NSData* key = [brokerHelper getBrokerKey:&error];
    if (!key)
    {
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Unable to retrieve broker key." correlationId:_correlationId];
        completionBlock([ADAuthenticationResult resultFromError:adError correlationId:_correlationId]);
        return;
    }
    
    NSString* base64Key = [NSString Base64EncodeData:key];
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    CHECK_FOR_NIL(base64UrlKey);
#endif // TARGET_OS_IPHONE Broker Message Encryption
    
    NSString* adalVersion = [ADLogger getAdalVersion];
    CHECK_FOR_NIL(adalVersion);
    
    NSDictionary* queryDictionary =
    @{
      @"authority"      : _context.authority,
      @"resource"       : _resource,
      @"client_id"      : _clientId,
      @"redirect_uri"   : _redirectUri,
      @"username_type"  : _identifier ? [_identifier typeAsString] : @"",
      @"username"       : _identifier.userId ? _identifier.userId : @"",
      @"force"          : _promptBehavior == AD_FORCE_PROMPT ? @"YES" : @"NO",
      @"correlation_id" : _correlationId,
#if TARGET_OS_IPHONE // Broker Message Encryption
      @"broker_key"     : base64UrlKey,
#endif // TARGET_OS_IPHONE Broker Message Encryption
      @"client_version" : adalVersion,
      BROKER_MAX_PROTOCOL_VERSION : @"2",
      @"extra_qp"       : _queryParams ? _queryParams : @"",
      };
    
    NSDictionary<NSString *, NSString *>* resumeDictionary =
  @{
    @"authority"        : _context.authority,
    @"resource"         : _resource,
    @"client_id"        : _clientId,
    @"redirect_uri"     : _redirectUri,
    @"correlation_id"   : _correlationId.UUIDString,
    };
    
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    if ([ADBrokerHelper canUseBroker])
    {
        [ADBrokerHelper invokeBroker:queryDictionary completionHandler:completionBlock];
    }
    else
    {
        [ADBrokerHelper promptBrokerInstall:queryDictionary completionHandler:completionBlock];
    }
}

@end

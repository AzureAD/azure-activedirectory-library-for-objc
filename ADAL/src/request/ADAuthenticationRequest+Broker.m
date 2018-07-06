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
#import "ADTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "ADTelemetryBrokerEvent.h"
#import "MSIDAuthority.h"
#import "MSIDKeychainTokenCache.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDBrokerResponse.h"
#import "ADResponseCacheHandler.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDDefaultTokenCacheAccessor.h"
#import "MSIDAADV1Oauth2Factory.h"


#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#import "ADBrokerKeyHelper.h"
#import "ADBrokerNotificationManager.h"
#import "ADKeychainUtil.h"
#import "MSIDBrokerResponse+ADAL.h"
#endif // TARGET_OS_IPHONE

NSString* s_brokerAppVersion = nil;
NSString* s_brokerProtocolVersion = nil;

NSString* kAdalResumeDictionaryKey = @"adal-broker-resume-dictionary";

@implementation ADAuthenticationRequest (Broker)

+ (BOOL)validBrokerRedirectUri:(NSString*)url
{
    (void)s_brokerAppVersion;
    (void)s_brokerProtocolVersion;
    
#if AD_BROKER
    // Allow the broker app to use a special redirect URI when acquiring tokens
    if ([url isEqualToString:ADAL_BROKER_APP_REDIRECT_URI])
    {
        return YES;
    }
#endif
    
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

/*!
    Process the broker response and call the completion block, if it is available.
 
    @return YES if the URL was a properly decoded broker response
 */
+ (BOOL)internalHandleBrokerResponse:(NSURL *)response
{
#if TARGET_OS_IPHONE
    __block ADAuthenticationCallback completionBlock = [ADBrokerHelper copyAndClearCompletionBlock];
    
    ADAuthenticationError* error = nil;
    ADAuthenticationResult* result = [self processBrokerResponse:response
                                                           error:&error];
    BOOL fReturn = YES;
    
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kAdalResumeDictionaryKey];
    if (!result)
    {
        result = [ADAuthenticationResult resultFromError:error];
        fReturn = NO;
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidReceieveResponseFromBroker
                                                        object:nil
                                                      userInfo:@{ @"response" : result }];
    
    // Regardless of whether or not processing the broker response succeeded we always have to call
    // the completion block.
    if (completionBlock)
    {
        completionBlock(result);
    }
    else if (fReturn)
    {
        MSID_LOG_ERROR(nil, @"Received broker response without a completionBlock.");
        
        [ADWebAuthController setInterruptedBrokerResult:result];
    }
    
    return fReturn;
#else
    (void)response;
    return NO;
#endif // TARGET_OS_IPHONE
}

/*!
    Processes the broker response from the URL
 
    @param  response    The URL the application received from the openURL: handler
    @param  error       (Optional) Any error that occurred trying to process the broker response (note: errors
                        sent in the response itself will be returned as a result, and not populate this parameter)

    @return The result contained in the broker response, nil if the URL could not be processed
 */
+ (ADAuthenticationResult *)processBrokerResponse:(NSURL *)response
                                            error:(ADAuthenticationError * __autoreleasing *)error
{
#if TARGET_OS_IPHONE

    if (!response)
    {
        
        return nil;
    }
    
    NSDictionary* resumeDictionary = [[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey];
    if (!resumeDictionary)
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_NO_RESUME_STATE, @"No resume state found in NSUserDefaults", nil);
        return nil;
    }
    
    NSUUID* correlationId = [[NSUUID alloc] initWithUUIDString:[resumeDictionary objectForKey:@"correlation_id"]];
    NSString* redirectUri = [resumeDictionary objectForKey:@"redirect_uri"];
    if (!redirectUri)
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_BAD_RESUME_STATE, @"Resume state is missing the redirect uri!", correlationId);
        return nil;
    }
    
    // Check to make sure this response is coming from the redirect URI we're expecting.
    if (![[[response absoluteString] lowercaseString] hasPrefix:[redirectUri lowercaseString]])
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE, @"URL not coming from the expected redirect URI!", correlationId);
        return nil;
    }
    
    // NSURLComponents resolves some URLs which can't get resolved by NSURL
    NSURLComponents* components = [NSURLComponents componentsWithURL:response resolvingAgainstBaseURL:NO];
    NSString *qp = [components percentEncodedQuery];
    //expect to either response or error and description, AND correlation_id AND hash.
    NSDictionary* queryParamsMap = [NSDictionary msidURLFormDecode:qp];
    
    if ([queryParamsMap valueForKey:MSID_OAUTH2_ERROR_DESCRIPTION])
    {
        MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:queryParamsMap error:nil];
        return [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    }
    
    // Encrypting the broker response should not be a requirement on Mac as there shouldn't be a possibility of the response
    // accidentally going to the wrong app
    NSString* hash = [queryParamsMap valueForKey:ADAL_BROKER_HASH_KEY];
    if (!hash)
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_HASH_MISSING, @"Key hash is missing from the broker response", correlationId);
        return nil;
    }
    
    NSString* encryptedBase64Response = [queryParamsMap valueForKey:ADAL_BROKER_RESPONSE_KEY];
    NSString* msgVer = [queryParamsMap valueForKey:ADAL_BROKER_MESSAGE_VERSION];
    NSInteger protocolVersion = 1;
    
    if (msgVer)
    {
        protocolVersion = [msgVer integerValue];
    }
    s_brokerProtocolVersion = msgVer;
    
    //decrypt response first
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError* decryptionError = nil;
    NSData *encryptedResponse = [NSString msidBase64UrlDecodeData:encryptedBase64Response ];
    NSData* decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse
                                                    version:protocolVersion
                                                      error:&decryptionError];
    if (!decrypted)
    {
        AUTH_ERROR_UNDERLYING(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED, @"Failed to decrypt broker message", decryptionError, correlationId)
        return nil;
    }
    
    
    NSString* decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    //now compute the hash on the unencrypted data
    NSString* actualHash = [ADPkeyAuthHelper computeThumbprint:decrypted isSha2:YES];
    if(![hash isEqualToString:actualHash])
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH, @"Decrypted response does not match the hash", correlationId);
        return nil;
    }
    
    // create response from the decrypted payload
    queryParamsMap = [NSDictionary msidURLFormDecode:decryptedString];
    [ADHelpers removeNullStringFrom:queryParamsMap];
    
    NSError *msidError = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:queryParamsMap error:&msidError];
    
    if (msidError)
    {
        return [ADAuthenticationResult resultFromMSIDError:msidError];
    }
    
    s_brokerAppVersion = brokerResponse.brokerAppVer;
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    NSString *keychainGroup = resumeDictionary[@"keychain_group"];
    
    if (AD_SUCCEEDED == result.status && keychainGroup)
    {
        MSIDKeychainTokenCache *dataSource = [[MSIDKeychainTokenCache alloc] initWithGroup:keychainGroup];
        MSIDOauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
        MSIDDefaultTokenCacheAccessor *otherAccessor = [[MSIDDefaultTokenCacheAccessor alloc] initWithDataSource:dataSource otherCacheAccessors:nil factory:factory];
        MSIDLegacyTokenCacheAccessor *cache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:dataSource otherCacheAccessors:@[otherAccessor] factory:factory];

        BOOL saveResult = [cache saveTokensWithBrokerResponse:brokerResponse
                                             saveSSOStateOnly:brokerResponse.isAccessTokenInvalid
                                                      context:nil
                                                        error:&msidError];
        
        if (!saveResult)
        {
            return [ADAuthenticationResult resultFromMSIDError:msidError];
        }
        
        NSString *userId = [[[result tokenCacheItem] userInformation] userId];
        [ADAuthenticationContext updateResult:result
                                       toUser:[ADUserIdentifier identifierWithId:userId]];
    }
    
    return result;
#else
    (void)response;
    AUTH_ERROR(AD_ERROR_UNEXPECTED, @"broker response parsing not supported on Mac", nil);
    return nil;
#endif
}

- (BOOL)canUseBroker
{
    return _context.credentialsType == AD_CREDENTIALS_AUTO && _context.validateAuthority == YES && [ADBrokerHelper canUseBroker] && ![MSIDAuthority isADFSInstance:_requestParams.authority];
}

- (NSURL *)composeBrokerRequest:(ADAuthenticationError* __autoreleasing *)error
{
    ARG_RETURN_IF_NIL(_requestParams.authority, _requestParams.correlationId);
    ARG_RETURN_IF_NIL(_requestParams.resource, _requestParams.correlationId);
    ARG_RETURN_IF_NIL(_requestParams.clientId, _requestParams.correlationId);
    ARG_RETURN_IF_NIL(_requestParams.correlationId, _requestParams.correlationId);
    
    if(![ADAuthenticationRequest validBrokerRedirectUri:_requestParams.redirectUri])
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI, ADRedirectUriInvalidError, _requestParams.correlationId);
        return nil;
    }
    
    MSID_LOG_INFO(_requestParams, @"Invoking broker for authentication");
#if TARGET_OS_IPHONE // Broker Message Encryption
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] init];
    NSData* key = [brokerHelper getBrokerKey:error];
    AUTH_ERROR_RETURN_IF_NIL(key, AD_ERROR_UNEXPECTED, @"Unable to retrieve broker key.", _requestParams.correlationId);
    
    NSString* base64Key = [NSString msidBase64UrlEncodeData:key];
    AUTH_ERROR_RETURN_IF_NIL(base64Key, AD_ERROR_UNEXPECTED, @"Unable to base64 encode broker key.", _requestParams.correlationId);
    NSString* base64UrlKey = [base64Key msidUrlFormEncode];
    AUTH_ERROR_RETURN_IF_NIL(base64UrlKey, AD_ERROR_UNEXPECTED, @"Unable to URL encode broker key.", _requestParams.correlationId);
#endif // TARGET_OS_IPHONE Broker Message Encryption
    
    NSString* adalVersion = ADAL_VERSION_NSSTRING;
    AUTH_ERROR_RETURN_IF_NIL(adalVersion, AD_ERROR_UNEXPECTED, @"Unable to retrieve ADAL version.", _requestParams.correlationId);
    
    NSDictionary* queryDictionary =
    @{
      @"authority"      : _requestParams.authority,
      @"resource"       : _requestParams.resource,
      @"client_id"      : _requestParams.clientId,
      @"redirect_uri"   : _requestParams.redirectUri,
      @"username_type"  : _requestParams.identifier ? [_requestParams.identifier typeAsString] : @"",
      @"username"       : _requestParams.identifier.userId ? _requestParams.identifier.userId : @"",
      @"force"          : _promptBehavior == AD_FORCE_PROMPT ? @"YES" : @"NO",
      @"skip_cache"     : _skipCache ? @"YES" : @"NO",
      @"correlation_id" : _requestParams.correlationId,
#if TARGET_OS_IPHONE // Broker Message Encryption
      @"broker_key"     : base64UrlKey,
#endif // TARGET_OS_IPHONE Broker Message Encryption
      @"client_version" : adalVersion,
      ADAL_BROKER_MAX_PROTOCOL_VERSION : @"2",
      @"extra_qp"       : _queryParams ? _queryParams : @"",
      @"claims"         : _claims ? _claims : @"",
      };
    
    NSDictionary<NSString *, NSString *> *resumeDictionary = nil;
#if TARGET_OS_IPHONE
        NSString *sharedGroup = self.sharedGroup ? self.sharedGroup : MSIDKeychainTokenCache.defaultKeychainGroup;
    
    resumeDictionary =
    @{
      @"authority"        : _requestParams.authority,
      @"resource"         : _requestParams.resource,
      @"client_id"        : _requestParams.clientId,
      @"redirect_uri"     : _requestParams.redirectUri,
      @"correlation_id"   : _requestParams.correlationId.UUIDString,
      @"keychain_group"   : sharedGroup
      };
#else
    resumeDictionary =
    @{
      @"authority"        : _requestParams.authority,
      @"resource"         : _requestParams.resource,
      @"client_id"        : _requestParams.clientId,
      @"redirect_uri"     : _requestParams.redirectUri,
      @"correlation_id"   : _requestParams.correlationId.UUIDString,
      };
#endif
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    NSString* query = [queryDictionary msidURLFormEncode];
    
    NSURL* brokerRequestURL = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker?%@", ADAL_BROKER_SCHEME, query]];
    AUTH_ERROR_RETURN_IF_NIL(brokerRequestURL, AD_ERROR_UNEXPECTED, @"Unable to encode broker request URL", _requestParams.correlationId);
    
    return brokerRequestURL;
}

@end

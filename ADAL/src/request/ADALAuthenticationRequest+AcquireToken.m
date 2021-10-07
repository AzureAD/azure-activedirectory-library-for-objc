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

#import "ADALAuthenticationRequest.h"
#import "ADALAuthenticationContext+Internal.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALAuthorityValidation.h"
#import "ADALHelpers.h"
#import "ADALUserIdentifier.h"
#import "ADALAcquireTokenSilentHandler.h"
#import "ADALTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "ADALTelemetryAPIEvent.h"
#import "ADALTelemetryBrokerEvent.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADALBrokerHelper.h"
#import "ADALAuthorityUtils.h"
#import "ADALEnrollmentGateway.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "ADALTokenCacheItem+MSIDTokens.h"
#import "MSIDAccessToken.h"
#import "ADALUserInformation.h"
#import "ADALResponseCacheHandler.h"
#import "MSIDAuthority.h"
#import "MSIDLegacyRefreshToken.h"
#import "MSIDAccountIdentifier.h"
#import "MSIDADFSAuthority.h"
#import "MSIDAuthorityFactory.h"
#import "MSIDClientCapabilitiesUtil.h"
#import "ADALAuthenticationErrorConverter.h"

#import "MSIDWebAADAuthResponse.h"
#import "MSIDWebMSAuthResponse.h"
#import "MSIDWebOpenBrowserResponse.h"
#import "MSIDADFSAuthority.h"
#import "MSIDAuthorityFactory.h"

#if TARGET_OS_IPHONE
#import "MSIDAppExtensionUtil.h"
#endif

@implementation ADALAuthenticationRequest (AcquireToken)

#pragma mark -
#pragma mark AcquireToken

- (void)acquireToken:(NSString *)apiId
     completionBlock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [[MSIDTelemetry sharedInstance] startEvent:self.telemetryRequestId
                                   eventName:MSID_TELEMETRY_EVENT_API_EVENT];
    
    AD_REQUEST_CHECK_ARGUMENT([_requestParams resource]);
    [self ensureRequest];
    NSString* telemetryRequestId = [_requestParams telemetryRequestId];
    
    NSString *logMessage = [NSString stringWithFormat:@"%@ idtype = %@", _silent ? @"Silent" : @"", [_requestParams.identifier typeAsString]];
    NSString *logMessagePII = [NSString stringWithFormat:@"resource = %@, clientId = %@, userId = %@", _requestParams.resource, _requestParams.clientId, _requestParams.identifier.userId];
    
    NSURL *authorityUrl = [NSURL URLWithString:_requestParams.authority];
    
    if ([ADALAuthorityUtils isKnownHost:authorityUrl]) {
        logMessage = [NSString stringWithFormat:@"%@ authority host: %@", logMessage, authorityUrl.host];
    } else {
        logMessagePII = [NSString stringWithFormat:@"%@ authority: %@", logMessagePII, _requestParams.authority];
    }
    
    MSID_LOG_INFO(_requestParams, @"##### BEGIN acquireToken %@ #####", logMessage);
    MSID_LOG_INFO_PII(_requestParams, @"##### BEGIN acquireToken %@ %@#####", logMessage, logMessagePII);
    
    ADAuthenticationCallback wrappedCallback = ^void(ADALAuthenticationResult* result)
    {
        if (result.status == AD_SUCCEEDED)
        {
            MSID_LOG_INFO(_requestParams, @"##### END succeeded. %@ #####", logMessage);
            MSID_LOG_INFO_PII(_requestParams, @"##### END succeeded. %@ %@ #####", logMessage, logMessagePII);
        }
        else
        {
            ADALAuthenticationError* error = result.error;
            MSID_LOG_INFO(_requestParams, @"##### END failed { domain: %@ code: %ld protocolCode: %@ %@ #####", error.domain, (long)error.code, error.protocolCode, logMessage);
            MSID_LOG_INFO_PII(_requestParams, @"#### END failed { domain: %@ code: %ld protocolCode: %@ errorDetails: %@ %@ %@ #####", error.domain, (long)error.code, error.protocolCode, error.errorDetails, logMessage, logMessagePII);
        }

        ADALTelemetryAPIEvent* event = [[ADALTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_API_EVENT
                                                                       context:self];
        [event setApiId:apiId];
        
        [event setCorrelationId:self.correlationId];
        [event setClientId:_requestParams.clientId];
        [event setAuthority:_context.authority];
        [event setExtendedExpiresOnSetting:[_requestParams extendedLifetime]? MSID_TELEMETRY_VALUE_YES:MSID_TELEMETRY_VALUE_NO];
        [event setPromptBehavior:_promptBehavior];
        if ([result tokenCacheItem])
        {
            [event setUserInformation:result.tokenCacheItem.userInformation];
        }
        else
        {
            [event setUserId:_requestParams.identifier.userId];
        }
        [event setResultStatus:result.status];
        [event setIsExtendedLifeTimeToken:[result extendedLifeTimeToken]? MSID_TELEMETRY_VALUE_YES:MSID_TELEMETRY_VALUE_NO];
        [event setErrorCode:[result.error code]];
        [event setErrorDomain:[result.error domain]];
        [event setProtocolCode:[[result error] protocolCode]];
        
        [[MSIDTelemetry sharedInstance] stopEvent:self.telemetryRequestId event:event];
        //flush all events in the end of the acquireToken call
        [[MSIDTelemetry sharedInstance] flush:self.telemetryRequestId];
        
        completionBlock(result);
    };
    
    if (_samlAssertion == nil && !_silent && ![NSThread isMainThread])
    {
        ADALAuthenticationError* error =
        [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_ON_MAIN_THREAD
                                               protocolCode:nil
                                               errorDetails:@"Interactive authentication requests must originate from the main thread"
                                              correlationId:_requestParams.correlationId];
        
        wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    if (![self checkExtraQueryParameters])
    {
        ADALAuthenticationError* error =
        [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"extraQueryParameters is not properly encoded. Please make sure it is URL encoded."
                                              correlationId:_requestParams.correlationId];
        wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    ADALAuthenticationError *error = nil;
    if (![self checkClaims:&error])
    {
        wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
        return;
    }
    
    if (!_silent && _context.credentialsType == AD_CREDENTIALS_AUTO)
    {
        if (![ADALAuthenticationRequest validBrokerRedirectUri:_requestParams.redirectUri])
        {
            ADALAuthenticationError* error =
            [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI
                                                   protocolCode:nil
                                                   errorDetails:ADRedirectUriInvalidError
                                                  correlationId:_requestParams.correlationId];
            wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
            return;
        }
        
        NSError *msidError;
        if (![ADALAuthenticationRequest verifyAdditionalRequiredSchemesAreRegistered:&msidError correlationID:_requestParams.correlationId])
        {
            ADALAuthenticationError *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:msidError];
            wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
            return;
        }
    }
    
    [[MSIDTelemetry sharedInstance] startEvent:telemetryRequestId eventName:MSID_TELEMETRY_EVENT_AUTHORITY_VALIDATION];
    
    ADALAuthorityValidation* authorityValidation = [ADALAuthorityValidation sharedInstance];
    [authorityValidation checkAuthority:_requestParams
                      validateAuthority:_context.validateAuthority
                        completionBlock:^(BOOL validated, ADALAuthenticationError *error)
     {
         ADALTelemetryAPIEvent* event = [[ADALTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_AUTHORITY_VALIDATION
                                                                        context:_requestParams];
         [event setAuthorityValidationStatus:validated ? MSID_TELEMETRY_VALUE_YES:MSID_TELEMETRY_VALUE_NO];
         [event setAuthority:_context.authority];
         [[MSIDTelemetry sharedInstance] stopEvent:telemetryRequestId event:event];
         
         if (error)
         {
             wrappedCallback([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
         }
         else
         {
             [self validatedAcquireToken:wrappedCallback];
         }
     }];    
}

- (BOOL)checkExtraQueryParameters
{
    if ([NSString msidIsStringNilOrBlank:_requestParams.extraQueryParameters])
    {
        return YES;
    }
    
    NSString* queryParams = _requestParams.extraQueryParameters.msidTrimmedString;
    if ([queryParams hasPrefix:@"&"])
    {
        queryParams = [queryParams substringFromIndex:1];
    }
    NSURL* url = [NSURL URLWithString:[NSMutableString stringWithFormat:@"%@?%@", _context.authority, queryParams]];
    
    return url!=nil;
}

- (BOOL)checkClaims:(ADALAuthenticationError *__autoreleasing *)error
{
    if ([NSString msidIsStringNilOrBlank:_claims])
    {
        return YES;
    }
    
    // Make sure claims is not in EQP
    NSDictionary *queryParamsDict = [NSDictionary msidDictionaryFromWWWFormURLEncodedString:_requestParams.extraQueryParameters];
    if (queryParamsDict[@"claims"])
    {
        if (error)
        {
            *error = [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                                            protocolCode:nil
                                                            errorDetails:@"Duplicate claims parameter is found in extraQueryParameters. Please remove it."
                                                           correlationId:_requestParams.correlationId];
        }
        return NO;
    }
    // Always skip access token cache if claims parameter is not nil/empty
    [_requestParams setForceRefresh:YES];

    return YES;
}

- (void)validatedAcquireToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    if (_refreshToken)
    {
        [self tryRefreshToken:completionBlock];
        return;
    }
    
    if (![ADALAuthenticationContext isForcedAuthorization:_promptBehavior] && !_skipCache)
    {
        [self getAccessToken:^(ADALAuthenticationResult *result) {
            if ([ADALAuthenticationContext isFinalResult:result])
            {
                completionBlock(result);
                return;
            }
            
            _underlyingError = result.error;
            
            [self requestToken:completionBlock];
        }];
        return;
    }
    
    [self requestToken:completionBlock];
}

- (void)getAccessToken:(ADAuthenticationCallback)completionBlock
{
    [[MSIDTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:MSID_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT];
    ADALAcquireTokenSilentHandler *request = [ADALAcquireTokenSilentHandler requestWithParams:_requestParams
                                                                               tokenCache:self.tokenCache
                                                                             verifyUserId:!_silent];
    
    [request getToken:^(ADALAuthenticationResult *result)
     {
         ADALTelemetryAPIEvent* event = [[ADALTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT
                                                                        context:_requestParams];
         [[MSIDTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
         completionBlock(result);
     }];
}

- (void)requestToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    NSUUID* correlationId = [_requestParams correlationId];

    if (_samlAssertion)
    {
        [self requestTokenByAssertion:^(MSIDTokenResponse *response, ADALAuthenticationError *error)
        {
            ADALAuthenticationResult *result = [ADALResponseCacheHandler processAndCacheResponse:response
                                                                            fromRefreshToken:nil
                                                                                       cache:self.tokenCache
                                                                                      params:_requestParams
                                                                               configuration:_requestParams.msidConfig
                                                                                verifyUserId:YES];
            completionBlock(result);
        }];
        return;
    }

    if (_silent)
    {
        
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown.
        //If the underlying error is AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED,
        //Intune MAM remediation is needed and we should pass that instead.
        ADALAuthenticationResult *result;
        if (AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED == _underlyingError.code)
        {
            result = [ADALAuthenticationResult resultFromError:_underlyingError correlationId:correlationId];
        }
        else
        {
            NSMutableDictionary *underlyingUserInfo = [NSMutableDictionary new];
            [underlyingUserInfo addEntriesFromDictionary:_underlyingError.userInfo];
            underlyingUserInfo[NSUnderlyingErrorKey] = _underlyingError;
            
            ADALAuthenticationError* error =
            [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_USER_INPUT_NEEDED
                                                   protocolCode:nil
                                                   errorDetails:ADCredentialsNeeded
                                                       userInfo:underlyingUserInfo
                                                  correlationId:correlationId];
            result = [ADALAuthenticationResult resultFromError:error correlationId:correlationId];
        }
        
        completionBlock(result);
        return;
    }

    //can't pop UI or go to broker in an extension
    if ([[[NSBundle mainBundle] bundlePath] hasSuffix:@".appex"])
    {
        // This is an app extension. Return an error unless a webview is specified by the
        // extension and embedded auth is being used.
        BOOL isEmbeddedWebView = (nil != _context.webView) && (AD_CREDENTIALS_EMBEDDED == _context.credentialsType);
        if (!isEmbeddedWebView)
        {
            ADALAuthenticationError* error =
            [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION
                                                   protocolCode:nil
                                                   errorDetails:ADInteractionNotSupportedInExtension
                                                  correlationId:correlationId];
            ADALAuthenticationResult* result = [ADALAuthenticationResult resultFromError:error correlationId:correlationId];
            completionBlock(result);
            return;
        }
    }

    [self requestTokenImpl:completionBlock];
}

- (void)requestTokenImpl:(ADAuthenticationCallback)completionBlock
{
#if TARGET_OS_IPHONE
    //call the broker.
    if ([self canUseBroker])
    {
        
#if !AD_BROKER
        if (![self takeExclusionLock:completionBlock])
        {
            return;
        }
#endif
        
        ADALAuthenticationError* error = nil;
        NSURL* brokerURL = [self composeBrokerRequest:&error];
        if (!brokerURL)
        {
            completionBlock([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
            return;
        }
        
        [[MSIDTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:MSID_TELEMETRY_EVENT_LAUNCH_BROKER];
        [ADALBrokerHelper invokeBroker:brokerURL completionHandler:^(ADALAuthenticationResult* result)
         {
             ADALTelemetryBrokerEvent* event = [[ADALTelemetryBrokerEvent alloc] initWithName:MSID_TELEMETRY_EVENT_LAUNCH_BROKER
                                                                                requestId:_requestParams.telemetryRequestId
                                                                            correlationId:_requestParams.correlationId];
             [event setResultStatus:[result status]];
             [event setBrokerAppVersion:s_brokerAppVersion];
             [event setBrokerProtocolVersion:s_brokerProtocolVersion];
             [[MSIDTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];

#if !AD_BROKER
             [ADALAuthenticationRequest releaseExclusionLock];
#endif
             
             // If we got back a valid RT but no access token, then replay the RT for a new AT.
             BOOL replay = [NSString msidIsStringNilOrBlank:result.tokenCacheItem.accessToken];
             if (result.status == AD_SUCCEEDED && replay)
             {
                 _requestParams.cloudAuthority = result.authority;
                 [self getAccessToken:completionBlock];
                 return;
             }
             
             completionBlock(result);
         }];
        return;
    }
#endif

    if (![self takeExclusionLock:completionBlock])
    {
        return;
    }

    // Always release the exclusion lock on completion
    ADAuthenticationCallback originalCompletionBlock = completionBlock;
    completionBlock = ^(ADALAuthenticationResult* result)
    {
        // If we got back a valid RT but no access token, then replay the RT for a new AT.
        BOOL replay = [NSString msidIsStringNilOrBlank:result.tokenCacheItem.accessToken];
        if (result.status == AD_SUCCEEDED && replay)
        {
            _requestParams.cloudAuthority = result.authority;
            [self getAccessToken:^(ADALAuthenticationResult *result) {
                [ADALAuthenticationRequest releaseExclusionLock];
                originalCompletionBlock(result);
            }];
            return;
        }
        else
        {
            [ADALAuthenticationRequest releaseExclusionLock];
            originalCompletionBlock(result);
        }
    };

    NSString* telemetryRequestId = [_requestParams telemetryRequestId];
    
    // Get the code first:
    [[MSIDTelemetry sharedInstance] startEvent:telemetryRequestId eventName:MSID_TELEMETRY_EVENT_AUTHORIZATION_CODE];
    
    [self requestCode:^(MSIDWebviewResponse *response, ADALAuthenticationError *error) {
        ADALTelemetryAPIEvent* event = [[ADALTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_AUTHORIZATION_CODE
                                                                       context:_requestParams];
        
        if (error)
        {
            ADALAuthenticationResult *result = (AD_ERROR_UI_USER_CANCEL == error.code) ? [ADALAuthenticationResult resultFromCancellation:_requestParams.correlationId]
            : [ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId];
            
            [event setAPIStatus:(AD_ERROR_UI_USER_CANCEL == error.code) ? MSID_TELEMETRY_VALUE_CANCELLED:MSID_TELEMETRY_VALUE_FAILED];
            [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
            completionBlock(result);
            return;
        }
#if TARGET_OS_IPHONE
        if ([self processMSAuthResponse:response telemetryEvent:event completionHandler:completionBlock])
        {
            return;
        }
#endif
        if ([self processOpenBrowserResponse:response telemetryEvent:event completionHandler:completionBlock])
        {
            return;
        }
        
       if (![self processOAuthResponse:response telemetryEvent:event completionHandler:completionBlock])
       {
           ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromError:[ADALAuthenticationError unexpectedInternalError:@"Received invalid response" correlationId:_context.correlationId]];
           [event setAPIStatus: MSID_TELEMETRY_VALUE_FAILED];
           [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
           
           completionBlock(result);
       }
    }];
}

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
           completionBlock:(MSIDTokenResponseCallback)completionBlock
{
    if (![code isKindOfClass:NSString.class] || [NSString msidIsStringNilOrBlank:code])
    {
        ADALAuthenticationError *error = [ADALAuthenticationError errorFromArgument:code argumentName:@"code" correlationId:_requestParams.correlationId];
        completionBlock(nil, error);
        return;
    }
    
    [self ensureRequest];
    
    MSID_LOG_VERBOSE(_requestParams, @"Requesting token by authorization code");
    MSID_LOG_VERBOSE_PII(_requestParams, @"Requesting token by authorization code for resource: %@", _requestParams.resource);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *requestData = [@{MSID_OAUTH2_GRANT_TYPE: MSID_OAUTH2_AUTHORIZATION_CODE,
                                          MSID_OAUTH2_CODE: code,
                                          MSID_OAUTH2_CLIENT_ID: [_requestParams clientId],
                                          MSID_OAUTH2_REDIRECT_URI: [_requestParams redirectUri],
                                          MSID_OAUTH2_CLIENT_INFO: @YES
                                          } mutableCopy];

    if (![NSString msidIsStringNilOrBlank:_requestParams.scopesString])
    {
        [requestData setValue:_requestParams.scopesString forKey:MSID_OAUTH2_SCOPE];
    }
    
    __auto_type adfsAuthority = [[MSIDADFSAuthority alloc] initWithURL:[NSURL URLWithString:_requestParams.authority] context:nil error:nil];
    BOOL isADFSInstance = adfsAuthority != nil;

    if (!isADFSInstance)
    {
        ADALAuthenticationError *error = nil;
        NSString *enrollId = [ADALEnrollmentGateway enrollmentIDForHomeAccountId:nil
                                                                          userID:_requestParams.identifier.userId
                                                                           error:&error];
        if (enrollId)
        {
            [requestData setObject:enrollId forKey:ADAL_MS_ENROLLMENT_ID];
        }
    }

    NSString *claims = [MSIDClientCapabilitiesUtil msidClaimsParameterFromCapabilities:_requestParams.clientCapabilities
                                                                       developerClaims:_requestParams.decodedClaims];

    if (![NSString msidIsStringNilOrBlank:claims])
    {
        [requestData setObject:claims forKey:MSID_OAUTH2_CLAIMS];
    }

    [self executeRequest:requestData
              completion:completionBlock];
}

- (void)tryRefreshToken:(ADAuthenticationCallback)completionBlock
{
    ADALAcquireTokenSilentHandler *request = [ADALAcquireTokenSilentHandler requestWithParams:_requestParams
                                                                               tokenCache:self.tokenCache
                                                                             verifyUserId:!_silent];
    
    // Construct a refresh token object to wrap up the refresh token provided by developer
    MSIDLegacyRefreshToken *refreshTokenItem = [[MSIDLegacyRefreshToken alloc] init];
    refreshTokenItem.refreshToken = _refreshToken;
    refreshTokenItem.accountIdentifier = [[MSIDAccountIdentifier alloc] initWithLegacyAccountId:_requestParams.identifier.userId homeAccountId:nil];
    __auto_type factory = [MSIDAuthorityFactory new];
    __auto_type authority = [factory authorityFromUrl:[NSURL URLWithString:_requestParams.authority] context:nil error:nil];
    refreshTokenItem.authority = authority;
    refreshTokenItem.clientId  = _requestParams.clientId;
    
    [request acquireTokenByRefreshToken:_refreshToken
                              cacheItem:refreshTokenItem
                       useOpenidConnect:YES
                        completionBlock:^(ADALAuthenticationResult *result)
     {
         completionBlock(result);
     }];
}

#if TARGET_OS_IPHONE
- (BOOL)processMSAuthResponse:(MSIDWebviewResponse *)response
               telemetryEvent:(ADALTelemetryAPIEvent *)event
            completionHandler:(ADAuthenticationCallback)completionHandler
{
    if (![response isKindOfClass:MSIDWebMSAuthResponse.class])
    {
        return NO;
    }
    
    [event setAPIStatus:@"try to prompt to install broker"];
    [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
    
    MSIDWebMSAuthResponse *authResponse = (MSIDWebMSAuthResponse *)response;
    
    ADALAuthenticationError *error = nil;
    NSURL* brokerRequestURL = [self composeBrokerRequest:&error];
    if (!brokerRequestURL)
    {
        ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId];
        [result setCloudAuthority:_cloudAuthority];
        completionHandler(result);
        return YES;
    }
    
    [ADALBrokerHelper promptBrokerInstall:[NSURL URLWithString:authResponse.appInstallLink]
                          brokerRequest:brokerRequestURL
                      completionHandler:completionHandler];
    return YES;
}
#endif

- (BOOL)processOpenBrowserResponse:(MSIDWebviewResponse *)response
                    telemetryEvent:(ADALTelemetryAPIEvent *)event
                 completionHandler:(ADAuthenticationCallback)completionHandler
{
    if (![response isKindOfClass:MSIDWebOpenBrowserResponse.class])
    {
        return NO;
    }
    
    NSURL *browserURL = ((MSIDWebOpenBrowserResponse *)response).browserURL;
    
    
#if TARGET_OS_IPHONE
    if (![MSIDAppExtensionUtil isExecutingInAppExtension])
    {
        MSID_LOG_INFO(nil, @"Opening a browser");
        MSID_LOG_INFO_PII(nil, @"Opening a browser - %@", browserURL);

        [MSIDAppExtensionUtil sharedApplicationOpenURL:browserURL];
    }
    else
    {
        ADALAuthenticationError *error = [ADALAuthenticationError errorWithDomain:ADAuthenticationErrorDomain
                                                                         code:AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION
                                                            protocolErrorCode:nil
                                                                 errorDetails:ADInteractionNotSupportedInExtension
                                                                correlationId:_requestParams.correlationId];
        
        ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId];
        
        [event setAPIStatus: MSID_TELEMETRY_VALUE_FAILED];
        [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
        
        completionHandler(result);
        return YES;
    }
#else
    [[NSWorkspace sharedWorkspace] openURL:browserURL];
#endif
    ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromCancellation:_requestParams.correlationId];
    
    [event setAPIStatus: MSID_TELEMETRY_VALUE_CANCELLED];
    [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
    
    completionHandler(result);
    return YES;
}

- (BOOL)processOAuthResponse:(MSIDWebviewResponse *)response
               telemetryEvent:(ADALTelemetryAPIEvent *)event
            completionHandler:(ADAuthenticationCallback)completionHandler
{
    if (![response isKindOfClass:MSIDWebOAuth2Response.class])
    {
        return NO;
    }
    
    MSIDWebOAuth2Response *oauthResponse = (MSIDWebOAuth2Response *)response;
    
    if (oauthResponse.authorizationCode)
    {
        if ([response isKindOfClass:MSIDWebAADAuthResponse.class])
        {
            [self setCloudInstanceHostname:((MSIDWebAADAuthResponse *)response).cloudHostName];
        }
        
        [event setAPIStatus:MSID_TELEMETRY_VALUE_SUCCEEDED];
        [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
        
        [[MSIDTelemetry sharedInstance] startEvent:_requestParams.telemetryRequestId eventName:MSID_TELEMETRY_EVENT_TOKEN_GRANT];
        
        [self requestTokenByCode:oauthResponse.authorizationCode
                 completionBlock:^(MSIDTokenResponse *tokenResponse, ADALAuthenticationError *error)
         {
             if (error)
             {
                 completionHandler([ADALAuthenticationResult resultFromError:error correlationId:_requestParams.correlationId]);
                 return;
             }
             
             ADALAuthenticationResult *result = [ADALResponseCacheHandler processAndCacheResponse:tokenResponse
                                                                             fromRefreshToken:nil
                                                                                        cache:self.tokenCache
                                                                                       params:_requestParams
                                                                                configuration:_requestParams.msidConfig
                                                                                 verifyUserId:!_silent];
             
             [result setCloudAuthority:_cloudAuthority];
             
             ADALTelemetryAPIEvent *event = [[ADALTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_TOKEN_GRANT
                                                                            context:_requestParams];
             [event setGrantType:MSID_TELEMETRY_VALUE_BY_CODE];
             [event setResultStatus:[result status]];
             [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
             
             completionHandler(result);
         }];
        return YES;
    }
    else
    {
        ADALAuthenticationResult *result = [ADALAuthenticationResult resultFromMSIDError:oauthResponse.oauthError];
        
        [event setAPIStatus: MSID_TELEMETRY_VALUE_FAILED];
        [[MSIDTelemetry sharedInstance] stopEvent:_requestParams.telemetryRequestId event:event];
        
        completionHandler(result);
        return YES;
    }
}


@end

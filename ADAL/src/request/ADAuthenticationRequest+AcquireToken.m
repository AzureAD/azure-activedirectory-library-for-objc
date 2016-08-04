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

#import "ADAuthenticationRequest.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADInstanceDiscovery.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheKey.h"
#import "ADAcquireTokenSilentHandler.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryAPIEvent.h"

@implementation ADAuthenticationRequest (AcquireToken)

#pragma mark -
#pragma mark AcquireToken

- (void)acquireToken:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT([_requestParams resource]);
    [self ensureRequest];
    
    [[ADTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:@"acauire_token_call"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acauire_token_call"];
        [self fillTelemetryForAcquireToken:event result:result];
        [[ADTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush];
        
        completionBlock(result);
    };
    
    NSString* log = [NSString stringWithFormat:@"acquireToken (authority = %@, resource = %@, clientId = %@, idtype = %@)",
                     [_requestParams authority], [_requestParams resource], [_requestParams clientId], [[_requestParams identifier] typeAsString]];
    AD_LOG_INFO_F(log, [_requestParams correlationId], @"userId = %@", [_requestParams identifier].userId);
    
    if (!_silent && ![NSThread isMainThread])
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_ON_MAIN_THREAD
                                               protocolCode:nil
                                               errorDetails:@"Interactive authentication requests must originate from the main thread"
                                              correlationId:[_requestParams correlationId]];
        
        requestCompletion([ADAuthenticationResult resultFromError:error]);
        return;
    }
    
    if (!_silent && _context.credentialsType == AD_CREDENTIALS_AUTO && ![ADAuthenticationRequest validBrokerRedirectUri:[_requestParams redirectUri]])
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI
                                               protocolCode:nil
                                               errorDetails:ADRedirectUriInvalidError
                                              correlationId:[_requestParams correlationId]];
        requestCompletion([ADAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]]);
        return;
    }
    
    if (!_context.validateAuthority)
    {
        [self validatedAcquireToken:requestCompletion];
        return;
    }
    
    [[ADTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:@"authority_validation"];
    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority
                                              requestParams:_requestParams
                                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"authority_validation"];
         [event setAuthorityValidationStatus:validated ? @"YES" : @"NO"];
         [event setAuthority:_context.authority];
         [[ADTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
         SAFE_ARC_RELEASE(event);

         if (error)
         {
             requestCompletion([ADAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]]);
         }
         else
         {
             [self validatedAcquireToken:requestCompletion];
         }
     }];

}

- (void)validatedAcquireToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    if (![ADAuthenticationContext isForcedAuthorization:_promptBehavior] && [_context hasCacheStore])
    {
        [ADAcquireTokenSilentHandler acquireTokenSilentForRequestParams:_requestParams
                                                        completionBlock:^(ADAuthenticationResult *result)
        {
            if ([ADAuthenticationContext isFinalResult:result])
            {
                completionBlock(result);
                return;
            }
            
            SAFE_ARC_RELEASE(_underlyingError);
            _underlyingError = result.error;
            SAFE_ARC_RETAIN(_underlyingError);
            
            [self requestToken:completionBlock];
        }];
        return;
    }
    
    [self requestToken:completionBlock];
}

- (void)requestToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    if (_samlAssertion)
    {
        [self requestTokenByAssertion:completionBlock];
        return;
    }

    if (_silent && !_allowSilent)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown:
        NSDictionary* underlyingError = _underlyingError ? @{NSUnderlyingErrorKey:_underlyingError} : nil;
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_USER_INPUT_NEEDED
                                               protocolCode:nil
                                               errorDetails:ADCredentialsNeeded
                                                   userInfo:underlyingError
                                              correlationId:[_requestParams correlationId]];
        
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]];
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
            ADAuthenticationError* error =
            [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION
                                                   protocolCode:nil
                                                   errorDetails:ADInteractionNotSupportedInExtension
                                                  correlationId:[_requestParams correlationId]];
            ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]];
            completionBlock(result);
            return;
        }
    }

#if !AD_BROKER
    //call the broker.
    if([self canUseBroker])
    {
        [self callBroker:completionBlock];
        return;
    }
#endif
    
    __block BOOL silentRequest = _allowSilent;
    
// Get the code first:
    [[ADTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:@"authorization_code"];
    [self requestCode:^(NSString * code, ADAuthenticationError *error)
     {
         ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"authorization_code"];
         [[ADTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
         SAFE_ARC_RELEASE(event);

         if (error)
         {
             if (silentRequest)
             {
                 _allowSilent = NO;
                 [self requestToken:completionBlock];
                 return;
             }
             
             ADAuthenticationResult* result = (AD_ERROR_UI_USER_CANCEL == error.code) ? [ADAuthenticationResult resultFromCancellation:[_requestParams correlationId]]
             : [ADAuthenticationResult resultFromError:error correlationId:[_requestParams correlationId]];
             completionBlock(result);
         }
         else
         {
             if([code hasPrefix:@"msauth://"])
             {
                 [self handleBrokerFromWebiewResponse:code
                                      completionBlock:completionBlock];
             }
             else
             {
                 [[ADTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:@"token_grant"];
                 [self requestTokenByCode:code
                          completionBlock:^(ADAuthenticationResult *result)
                  {
                      ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"token_grant"];
                      [[ADTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
                      SAFE_ARC_RELEASE(event);
                      
                      if (AD_SUCCEEDED == result.status)
                      {
                          [[_requestParams tokenCache] updateCacheToResult:result cacheItem:nil refreshToken:nil requestParams:_requestParams];
                          result = [ADAuthenticationContext updateResult:result toUser:[_requestParams identifier]];
                      }
                      completionBlock(result);
                  }];
             }
         }
     }];
}

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
           completionBlock:(ADAuthenticationCallback)completionBlock
{
    HANDLE_ARGUMENT(code, [_requestParams correlationId]);
    [self ensureRequest];
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", [_requestParams correlationId], @"Requesting token by authorization code for resource: %@", [_requestParams resource]);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         OAUTH2_AUTHORIZATION_CODE, OAUTH2_GRANT_TYPE,
                                         code, OAUTH2_CODE,
                                         [_requestParams clientId], OAUTH2_CLIENT_ID,
                                         [_requestParams redirectUri], OAUTH2_REDIRECT_URI,
                                         nil];
    if(![NSString adIsStringNilOrBlank:_scope])
    {
        [request_data setValue:_scope forKey:OAUTH2_SCOPE];
    }
    
    [self executeRequest:request_data
              completion:completionBlock];
}

- (void)fillTelemetryForAcquireToken:(ADTelemetryAPIEvent*)event
                              result:(ADAuthenticationResult*)result
{
    [event setCorrelationId:[_requestParams correlationId]];
    [event setUserId:[[_requestParams identifier] userId]];
    [event setClientId:[_requestParams clientId]];
    [event setResultStatus:[result status]];
    [event setIsExtendedLifeTimeToken:[result extendedLifeTimeToken]? @"YES":@"NO"];
    [event setErrorCode:[NSString stringWithFormat:@"%ld",(long)[result.error code]]];
    [event setErrorDomain:[result.error domain]];
    [event setProtocolCode:[[result error] protocolCode]];
    [event setErrorDescription:[[result error] errorDetails]];
}

@end

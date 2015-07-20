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

#import <Foundation/Foundation.h>
#import "NSString+ADHelperMethods.h"
#import "ADWebRequest.h"
#import "ADOAuth2Constants.h"
#import "NSString+ADHelperMethods.h"
#import "ADAuthenticationResult+Internal.h"
#import "NSDictionary+ADExtensions.h"
#import <workplaceJoinAPI/WorkPlaceJoin.h>
#import "ADBrokerContext.h"
#import "ADBrokerConstants.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import "ADBrokerHelpers.h"
#import "ADBrokerPRTCacheItem.h"
#import "ADBrokerUserAccount.h"
#import "ADBrokerSettings.h"
#import "ADLogger+Broker.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationContext+Internal.h"

#define AD_BROKER_FORCE_CANCEL_CODE -2

#define CURRENT_BROKER_VERSION 1

NSString* const ADBrokerContextDidReturnToAppNotification = @"ADBrokerContextDidReturnToAppNotification";
NSString* const ADBrokerFailedNotification = @"ADBrokerFailedNotification";

@implementation ADBrokerContext
{
    int _wpjRetryAttempt;
    NSDate* _initialAttemptTime;
}

- (id) init
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id) initWithAuthority:(NSString*) authority
{
    API_ENTRY;
    self = [super init];
    if(self)
    {
        _authority = authority;
        [ADLogger resetAdalVersion];
    }
    
    return self;
}

static dispatch_semaphore_t s_cancelSemaphore;
+ (void)initialize
{
    s_cancelSemaphore = dispatch_semaphore_create(0);
}

+ (void)openAppInBackground:(NSString *)application
                   response:(NSString *)response
{
    NSURL* appUrl = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@/broker?%@", application, response]];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] openURL:appUrl];
    });
}


+ (BOOL) handleNilOrEmptyAsResult:(NSObject*) argumentValue
                     argumentName: (NSString*) argumentName
             authenticationResult: (ADAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName];
        *authenticationResult = [ADAuthenticationResult resultFromError:argumentError];
        return NO;
    }
    
    return YES;
}

/*! Verifies that the string parameter is not nil or empty. If it is,
 the method generates an error and set it to an authentication result.
 Then the method calls the callback with the result.
 The method returns if the argument is valid. If the method returns false,
 the calling method should return. */
+(BOOL) checkAndHandleBadArgument: (NSObject*) argumentValue
                     argumentName: (NSString*) argumentName
                  completionBlock: (ADAuthenticationCallback)completionBlock
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:argumentError];
        completionBlock(result);//Call the callback to tell about the result
        return NO;
    }
    else
    {
        return YES;
    }
}

+ (BOOL) isBrokerRequest: (NSURL*) requestPayloadUrl
               returnUpn: (NSString**) returnUpn
{
    
    API_ENTRY;
    NSString* upn = nil;
    if (requestPayloadUrl == nil)
        return NO;
    
    NSString* host = [requestPayloadUrl host];
    
    BOOL isBrokerRequest = [host isEqualToString:@"broker"] || [host isEqualToString:@"wpj"];
    if (!isBrokerRequest)
    {
        return NO;
    }

    NSArray * parts = [[requestPayloadUrl absoluteString] componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    if(![NSString adIsStringNilOrBlank:[queryParamsMap valueForKey:USERNAME]])
    {
        upn = [queryParamsMap valueForKey:USERNAME];
    }
    
    // If we didn't get the UPN from the USERNAME param check if login_hint is being passed in
    if ([NSString adIsStringNilOrBlank:upn])
    {
        NSString* extraQP = [queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS];
        NSDictionary* extraQpDictionary = [NSDictionary adURLFormDecode:extraQP];
        NSString* loginHint = [extraQpDictionary valueForKey:@"login_hint"];
        if (![NSString adIsStringNilOrBlank:loginHint])
        {
            upn = loginHint;
        }
    }
    
    if (returnUpn)
    {
        *returnUpn = upn;
    }
    
    return YES;
}


+ (void) cancelRequest: (NSURL*) requestPayload
{
    
    API_ENTRY;
    
    ADAuthenticationError* error = nil;
    
    THROW_ON_NIL_ARGUMENT(requestPayload);
    NSArray * parts = [[requestPayload absoluteString] componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]);
    error = [ADAuthenticationError errorFromAuthenticationError:AD_USER_CANCELLED
                                                   protocolCode:nil
                                                   errorDetails:@"User cancelled authentication flow"];
    AD_LOG_ERROR_F(@"Autentication error", AD_USER_CANCELLED , @"User cancelled authentication flow", nil);
    NSString* response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@",
                           [error.protocolCode adUrlFormEncode],
                           [error.errorDetails adUrlFormEncode],
                           [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
    [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI] response:response];
}

+ (void) invokeBroker: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
{
    [ADBrokerContext invokeBroker:requestPayload
                sourceApplication:sourceApplication
                              upn:nil];
}

+ (void) invokeBroker: (NSString*) requestPayload
    sourceApplication: (NSString*) sourceApplication
                  upn: (NSString*) upn
{
    NSString* msg = [NSString stringWithFormat:@"Broker invoked from %@", sourceApplication];
    AD_LOG_INFO_F(msg, @"upn: %@, requestPayload: %@", upn, requestPayload);
    ADAuthenticationError* cancelError = [ADAuthenticationError errorQuietWithAuthenticationError:AD_BROKER_FORCE_CANCEL_CODE
                                                                                     protocolCode:nil
                                                                                     errorDetails:@"Broker forcing ADAL to cancel."];
    BOOL fSessionCancelled = [[ADAuthenticationBroker sharedInstance] cancelWithError:cancelError];
    if (!fSessionCancelled)
    {
        // If there was nothing to cancel then we can call the impl immediately
        [ADBrokerContext invokeBrokerImpl:requestPayload
                        sourceApplication:sourceApplication
                                      upn:upn];
        return;
    }
    
    AD_LOG_INFO(@"Previous ADAL session was cancelled.", nil);
    // If we had to cancel a previously running ADAL session then kick over to a background thread and block waiting on the
    // semaphore to be signalled. Once that happens we'll jump back onto the main thread and continue onwards.
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dispatch_semaphore_wait(s_cancelSemaphore, DISPATCH_TIME_FOREVER);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [ADBrokerContext invokeBrokerImpl:requestPayload
                            sourceApplication:sourceApplication
                                          upn:upn];
        });
    });
}

+ (void)takeMeBack:(ADAuthenticationResult*)result
 sourceApplication:(NSString*)sourceApplication
               upn:(NSString*)upn
       queryParams:(NSDictionary*)queryParamsMap
{
    ADAuthenticationError* error = result.error;
    if (error != nil && error.code == AD_BROKER_FORCE_CANCEL_CODE)
    {
        AD_LOG_INFO(@"Previous ADAL Session Cancelled", nil);
        dispatch_semaphore_signal(s_cancelSemaphore);
        // In this case we had to cancel this session, don't go back to the app.
        return;
    }
    
    if([NSString adSame:sourceApplication toString:DEFAULT_GUID_FOR_NIL])
    {
        AD_LOG_INFO(@"Not flipping back, source application was nil", nil);
        return;
    }
    
    NSString* response = nil;

    if(result.status == AD_SUCCEEDED)
    {
        AD_LOG_INFO_F(@"acquireToken succeeded.", @"Found token for %@", result.tokenCacheStoreItem.userInformation.getUpn);
        NSString* rawIdToken = @"";
        if(result.tokenCacheStoreItem.userInformation){
            rawIdToken = result.tokenCacheStoreItem.userInformation.rawIdToken;
        }
        
        response = [NSString stringWithFormat:@"authority=%@&client_id=%@&resource=%@&user_id=%@&correlation_id=%@&access_token=%@&refresh_token=%@&id_token=%@&expires_on=%f",
                    [queryParamsMap valueForKey:AUTHORITY],
                    [queryParamsMap valueForKey:OAUTH2_CLIENT_ID],
                    [queryParamsMap valueForKey:OAUTH2_RESOURCE],
                    upn,
                    [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE],
                    result.accessToken,
                    result.tokenCacheStoreItem.refreshToken,
                    rawIdToken,
                    [result.tokenCacheStoreItem.expiresOn timeIntervalSince1970]];
        
        NSString* brokerKey = [queryParamsMap valueForKey:BROKER_KEY];
        NSData *decodedKey = [NSString Base64DecodeData:brokerKey];
        NSString *decodedKeyString = [[NSString alloc] initWithData:decodedKey encoding:NSASCIIStringEncoding];
        
        NSData *plainData = [response dataUsingEncoding:NSUTF8StringEncoding];
        NSData* responseData = [ADBrokerHelpers encryptData:plainData key:decodedKeyString];
        
        response = [NSString stringWithFormat:@"response=%@&hash=%@", [[NSString Base64EncodeData: responseData] adUrlFormEncode], [ADBrokerHelpers computeHash:plainData]];
    } else{
        AD_LOG_ERROR_F(@"acquireToken failed.", result.error.code, @"error details: %@", result.error.errorDetails);
        response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@", [result.error.protocolCode adUrlFormEncode], [result.error.errorDetails adUrlFormEncode], [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
    }
    
    NSString* returnMsg = [NSString stringWithFormat:@"Returning to app (%@)", [queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]];
    AD_LOG_INFO_F(returnMsg, @"response: %@", response);
    [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI] response:response];
}

#define BROKER_FAILURE(_details, _code) {\
    AD_LOG_ERROR(_details, AD_FAILED, nil); \
    NSDictionary* _failInfo = @{ @"errorcode" : [NSNumber numberWithInteger:_code], @"errordetails" : _details }; \
    [[NSNotificationCenter defaultCenter] postNotificationName:ADBrokerFailedNotification object:nil userInfo:_failInfo]; \
    return NO; \
}

#define BROKER_VALIDATE_PARAM(_field) {\
    if (!_field) { \
        NSString* _details = @#_field " was not provided. Broker unable to continue."; \
        BROKER_FAILURE(_details, ADBrokerMissingParameterError); \
    } \
}

#define BROKER_VALIDATE_QUERYPARAM(_qp, _key, _field) { \
    _field = [_qp valueForKey:_key]; \
    if (!_field) { \
        NSString* _details = [NSString stringWithFormat:@"Malformed message. \"%@\" missing from broker query parameters.", _key]; \
        BROKER_FAILURE(_details, ADBrokerMissingRequestParameterError); \
    } else if (![_field isKindOfClass:[NSString class]]) {\
        NSString* _details = [NSString stringWithFormat:@"\"%@\" is the wrong type, expected NSString, actual %@", _key, NSStringFromClass([_field class])]; \
        BROKER_FAILURE(_details, ADBrokerMalformedRequestParameterError); \
        return NO; \
    } \
}

+ (BOOL)invokeBrokerImpl:(NSString *)requestPayload
       sourceApplication:(NSString *)sourceApplication
                     upn:(NSString *)upn
{
    API_ENTRY;
    
    
    BROKER_VALIDATE_PARAM(requestPayload);
    BROKER_VALIDATE_PARAM(sourceApplication);
    
    NSArray * parts = [requestPayload componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    
    NSString* authority = [queryParamsMap valueForKey:AUTHORITY];
    NSString* clientId = [queryParamsMap valueForKey:OAUTH2_CLIENT_ID];
    NSString* resource = [queryParamsMap valueForKey:OAUTH2_RESOURCE];
    NSString* redirectUri = [queryParamsMap valueForKey:OAUTH2_REDIRECT_URI];
    NSString* brokerKey = [queryParamsMap valueForKey:BROKER_KEY];
    NSString* clientAdalVer = [queryParamsMap valueForKey:CLIENT_ADAL_VERSION];
    
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, AUTHORITY, authority);
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, OAUTH2_CLIENT_ID, clientId);
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, OAUTH2_RESOURCE, resource);
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, OAUTH2_REDIRECT_URI, redirectUri);
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, BROKER_KEY, brokerKey);
    BROKER_VALIDATE_QUERYPARAM(queryParamsMap, CLIENT_ADAL_VERSION, clientAdalVer);
    
    // Allow for future versions of ADAL to pass in a minimum broker version that we can check against to
    // see if we need to to force an update
    NSString* minBrokerVerStr = [queryParamsMap valueForKey:MINIMUM_BROKER_VERSION];
    if (minBrokerVerStr && [minBrokerVerStr isKindOfClass:[NSString class]])
    {
        NSInteger minBrokerVer = [minBrokerVerStr integerValue];
        if (minBrokerVer == 0 && ![minBrokerVerStr isEqualToString:@"0"])
        {
            // -[NSString integerValue] returns 0 if the string did not represent a valid integer. Check for that and log
            // a sensical error message.
            NSString* log = [NSString stringWithFormat:@"Received bad minimum broker version \"%@\"", minBrokerVerStr];
            BROKER_FAILURE(log, ADBrokerMalformedRequestParameterError);
        }
        else if (minBrokerVer > CURRENT_BROKER_VERSION)
        {
            NSString* log = [NSString stringWithFormat:@"Received request for unsupported broker version (%ld), only support up to (%d)", (long)minBrokerVer, CURRENT_BROKER_VERSION];
            BROKER_FAILURE(log, ADBrokerUpdateNeededError);
        }
    }
    
    //validate source application against redirect uri
    NSURL *redirectURL = [[NSURL alloc] initWithString:redirectUri];
    if(![NSString adSame:sourceApplication toString:[redirectURL host]])
    {
        ADAuthenticationError* error = nil;
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_ARGUMENT
                                                       protocolCode:nil
                                                       errorDetails:@"source application bundle identifier should be same as the redirect URI domain"];
        AD_LOG_ERROR_F(@"source application does not match redirect uri host", (int)error.protocolCode , @"Invalid source app: %@", error.errorDetails);
        NSString* response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@",
                               [error.protocolCode adUrlFormEncode],
                               [error.errorDetails adUrlFormEncode],
                               [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
        [ADBrokerContext openAppInBackground:redirectUri response:response];
        return NO;
    }
    
    ADAuthenticationCallback takeMeBack = ^(ADAuthenticationResult *result)
    {
        [ADBrokerContext takeMeBack:result sourceApplication:sourceApplication upn:upn queryParams:queryParamsMap];
        [[NSNotificationCenter defaultCenter] postNotificationName:ADBrokerContextDidReturnToAppNotification
                                                            object:self];
    };
    
    [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
    ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:AUTHORITY];
    
    if (!ctx)
    {
        AD_LOG_ERROR_F(@"Failed to create broker context", AD_FAILED, @"broker context failed with authority: %@", AUTHORITY);
        takeMeBack([ADAuthenticationResult resultFromError:[ADAuthenticationError unexpectedInternalError:@"failed to create broker context."]]);
        return NO;
    }
    
    //update version after creating ADBrokerContext instance because the instance creation
    //sets the client ADAL version to 0.0.0
    [ADLogger setAdalVersion:clientAdalVer];
    ctx.correlationId = [[NSUUID alloc]
                         initWithUUIDString:[queryParamsMap
                                             valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
    
    NSString* reqExtraQP = [queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS];
    NSDictionary* extraQpDictionary = [NSDictionary adURLFormDecode:reqExtraQP];
    NSString* extraQP = [self filteredQPString:extraQpDictionary];
    
    NSString* userType = [queryParamsMap valueForKey:@"username_type"];
    if ([NSString adIsStringNilOrBlank:userType])
    {
        NSString* loginHint = [extraQpDictionary valueForKey:@"login_hint"];
        if (![NSString adIsStringNilOrBlank:loginHint])
        {
            userType = [ADUserIdentifier stringForType:OptionalDisplayableId];
        }
    }
    BOOL force = NO;
    NSString* nsForce = [queryParamsMap valueForKey:@"force"];
    if (nsForce && [nsForce isKindOfClass:[NSString class]])
    {
        force = [nsForce isEqualToString:@"YES"];
    }
    ADUserIdentifier* userId = [ADUserIdentifier identifierWithId:upn typeFromString:userType];
    
    AD_LOG_INFO_F(@"Client App parameters", @"authority=%@; client_id=%@; resource=%@; redirect_uri=%@; client_adal_version=%@; usertype=%@; upn_provided=%@;",
                  authority, clientId, resource, redirectUri, clientAdalVer, userType, ![NSString adIsStringNilOrBlank:upn] ? @"YES" : @"NO");
    
    [ctx acquireAccount:authority
                 userId:userId
               clientId:clientId
               resource:resource
            redirectUri:redirectUri
   extraQueryParameters:extraQP
                 appKey:brokerKey
                  force:force
        completionBlock:^(ADAuthenticationResult *result)
     {
         
         if(result.status != AD_SUCCEEDED && result.error.code == AD_ERROR_WPJ_REQUIRED)
         {
             AD_LOG_INFO(@"acquireAccount returned AD_ERROR_WPJ_REQUIRED error", nil);
             ADAuthenticationError* err = result.error;
             NSString* upn = [err.userInfo valueForKey:@"username"];
             __block ADUserIdentifier* userId = [ADUserIdentifier identifierWithId:upn];
             [ctx doWorkPlaceJoinForIdentifier:userId
                                 onResultBlock:^(NSError *error)
              {
                  if(!error)
                  {
                      AD_LOG_INFO(@"WPJ succeeded. Getting the token initially requested.", nil);
                      [ctx acquireAccount:[queryParamsMap valueForKey:AUTHORITY]
                                   userId:userId
                                 clientId:[queryParamsMap valueForKey:OAUTH2_CLIENT_ID]
                                 resource:[queryParamsMap valueForKey:OAUTH2_RESOURCE]
                              redirectUri:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]
                     extraQueryParameters:extraQP
                                   appKey:[queryParamsMap valueForKey:BROKER_KEY]
                                    force:force
                          completionBlock:takeMeBack];
                  }
                  else
                  {
                      AD_LOG_ERROR(@"WPJ failed.", error.code, error.description);
                      takeMeBack([ADAuthenticationResult resultFromError:[ADAuthenticationError errorFromNSError:error errorDetails:error.description]]);
                      return;
                  }
              }];
         }
         else
         {
             //either succeeded or a non-WPJ failure. Take the user back
             //to the calling app.
             takeMeBack(result);
             return;
         }
     }];
    
    return YES;
}

+ (NSString*)filteredQPString:(NSDictionary*)queryParams
{
    NSArray* allowedQPs = @[ @"mamver", @"msafed" ];
    
    NSMutableString* qpString = [NSMutableString stringWithString:@"nux=1"];
    for ( NSString* allowedQP in allowedQPs )
    {
        NSString* qpVal = [queryParams valueForKey:allowedQP];
        if (qpVal)
        {
            if (qpString)
            {
                [qpString appendFormat:@"&%@=%@", allowedQP, qpVal];
            }
            else
            {
                qpString = [NSMutableString stringWithFormat:@"%@=%@", allowedQP, qpVal];
            }
        }
    }
    
    return qpString;
}

+ (NSArray*) getAllAccounts:(ADAuthenticationError*) error
{
    API_ENTRY;
    NSMutableArray* accountsArray = [NSMutableArray new];
    id<ADTokenCacheStoring> cache = [ADBrokerKeychainTokenCacheStore new];
    
    NSError* errObj = nil;
    RegistrationInformation* regInfo = [[WorkPlaceJoin WorkPlaceJoinManager]
                                        getRegistrationInformation:nil];
    NSString* wpjUpn = nil;
    if(regInfo)
    {
        wpjUpn = regInfo.userPrincipalName;
        regInfo = nil;
    }
    
    if(errObj)
    {
        error = [ADAuthenticationError errorFromNSError:errObj
                                           errorDetails:errObj.description];
        return accountsArray;
    }
    
    error = nil;
    NSArray* array = [cache allItemsWithError:&error];
    
    if (error)
    {
        return accountsArray;
    }
    
    NSMutableSet* users = [NSMutableSet new];
    for(ADTokenCacheStoreItem* item in array)
    {
        ADUserInformation *user = item.userInformation;
        if (!item.userInformation)
        {
            user = [ADUserInformation userInformationWithUserId:@"Unknown user" error:nil];
        }
        if (![users containsObject:user.userId])
        {
            AD_LOG_INFO_F(@"Found Broker User", @"%@", user.userId);
            [users addObject:user.userId];
            [accountsArray addObject:[[ADBrokerUserAccount alloc] init:user
                                                     isWorkplaceJoined:[NSString adSame:[user.userId lowercaseString]
                                                                               toString:[wpjUpn lowercaseString]]
                                                          isNGCEnabled:NO]];
        }
    }
    
    return accountsArray;
}


- (void) acquireAccount:(NSString*) authority
                 userId:(ADUserIdentifier*) identifier
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
   extraQueryParameters:(NSString*) queryParams
                 appKey:(NSString*) appKey
                  force:(BOOL) force
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    ADAuthenticationError* error = nil;
    [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
    //if client id is not broker, use incoming app's key for cache.
    id<ADTokenCacheStoring> cache = [[ADBrokerKeychainTokenCacheStore alloc]initWithAppKey:appKey];
    ADAuthenticationContext* ctx = [[ADAuthenticationContext alloc]
                                    initWithAuthority:authority
                                    validateAuthority:YES
                                    tokenCacheStore:cache
                                    error:&error];
    [ctx setCorrelationId:_correlationId];
    
    // if UPN is blank, do not use acquire token silent as it will return
    // the default token in the case in case there is a single user.
    BOOL forceUI = [NSString adIsStringNilOrBlank:identifier.userId] || force;
    
    
    NSString* qp = @"brkr=1";
    if(queryParams)
    {
        qp = [NSString stringWithFormat:@"%@&%@", @"brkr=1", queryParams];
    }
    
    //callback implementation
    ADAuthenticationCallback defaultCallback = ^(ADAuthenticationResult *result) {
        //if failed, check for and use PRT
        if(result.status == AD_SUCCEEDED)
        {
            AD_LOG_INFO(@"acquireAccount - SUCCESS", @"Add refresh token to result and call completion block");
            [self addRefreshTokenTo:result fromCache:cache];
            completionBlock(result);
            return;
        }
        else
        {
            //call failed. check if the user is WPJ.
            if([self isWorkplaceJoined:identifier.userId])
            {
                AD_LOG_INFO(@"acquireAccount - FAILED", @"Workplace joined = true. Attempt to get token using PRT");
                ADAuthenticationError* error = nil;
                ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc] initWithIdentifier:identifier
                                                                                  authority:authority
                                                                              correlationId:_correlationId
                                                                                      error:&error];
                [prtCtx acquireTokenUsingPRTForResource:resource
                                               clientId:clientId
                                            redirectUri:redirectUri
                                                 appKey:appKey
                                        completionBlock:^(ADAuthenticationResult *result) {
                                            
                                            if(result.status == AD_SUCCEEDED)
                                            {
                                                AD_LOG_INFO(@"token using PRT call - SUCCESS", @"Add refresh token to result and call completion block");
                                                [self addRefreshTokenTo:result
                                                              fromCache:cache];
                                            }
                                            
                                            completionBlock(result);
                                            return;
                                        }];
            }
            else
            {
                if(![NSString adIsStringNilOrBlank:identifier.userId])
                {
                    AD_LOG_INFO(@"acquireAccount - FAILED", @"Workplace joined = FALSE. UPN was provided and silent cache lookup failed. Get a new token via UI.");
                    [ctx requestTokenWithResource:resource
                                                 clientId:clientId
                                              redirectUri:[NSURL URLWithString:redirectUri]
                                           promptBehavior:AD_PROMPT_AUTO
                                                   silent:NO
                                                   userId:identifier
                                                    scope:nil
                                     extraQueryParameters:qp
                                            correlationId:ctx.getCorrelationId
                                          completionBlock:^(ADAuthenticationResult *result) {
                                              
                                              if(result.status == AD_SUCCEEDED)
                                              {
                                                  [self addRefreshTokenTo:result
                                                                fromCache:cache];
                                              }
                                              
                                              completionBlock(result);
                                              return;
                                          }];
                }
                else
                {
                    completionBlock(result);
                    return;
                }
            }
        }
    };
    
    //if forceUI then pass AD_PROMPT_ALWAYS.
    if(forceUI)
    {
        AD_LOG_INFO(@"Force UI Prompt", @"UPN is nil so ignore cache. Use PROMPT_ALWAYS to force UI.");
        [ctx internalAcquireTokenWithResource:resource
                                     clientId:clientId
                                  redirectUri:[NSURL URLWithString:redirectUri]
                               promptBehavior:AD_PROMPT_ALWAYS
                                       silent:NO
                               userIdentifier:identifier
                                        scope:nil
                         extraQueryParameters:@"nux=1&brkr=1"
                            validateAuthority:YES
                                correlationId:ctx.getCorrelationId
                              completionBlock:defaultCallback];
    }
    else
    {
        // try cache in silent first. if that fails, callback checks for WPJ.
        // If the user is not WPJ then use default UI
        
        AD_LOG_INFO(@"UPN provided", @"do silent cache lookup.");
        [ctx acquireTokenSilentWithResource:resource
                                   clientId:clientId
                                redirectUri:[NSURL URLWithString:redirectUri]
                                     userId:identifier.userId
                            completionBlock:defaultCallback];
    }
    
}


- (void) acquireAccount:(ADUserIdentifier*) identifier
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireAccount:_authority
                  userId:identifier
                clientId:BROKER_CLIENT_ID
                resource:[ADBrokerSettings sharedInstance].graphResourceEndpoint
             redirectUri:BROKER_REDIRECT_URI
    extraQueryParameters:@"nux=1"
                  appKey:DEFAULT_GUID_FOR_NIL
                   force:NO
         completionBlock:completionBlock];
}


// to be used when user invokes add account flow from the app
- (void) acquireAccount:(ADUserIdentifier*) identifier
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireAccount:_authority
                  userId:identifier
                clientId:clientId
                resource:resource
             redirectUri:redirectUri
    extraQueryParameters:@"nux=1"
                  appKey:DEFAULT_GUID_FOR_NIL
                   force:YES
         completionBlock:completionBlock];
}

- (void) doWorkPlaceJoinForIdentifier:(ADUserIdentifier*)identifier
                        onResultBlock:(WPJCallback)onResultBlock
{
    
    API_ENTRY;
    WorkPlaceJoin *workPlaceJoinApi = [WorkPlaceJoin WorkPlaceJoinManager];
    NSError* error;
    error = [workPlaceJoinApi addWPJEnvironment:[ADBrokerSettings sharedInstance].wpjEnvironment];
    if(error)
    {
        onResultBlock(error);
        return;
    }
    
    
    AD_LOG_INFO_F(@"WPJ Discovery", @"do discovery in %u", [ADBrokerSettings sharedInstance].wpjEnvironment);
    [workPlaceJoinApi doDiscoveryForUpn:identifier.userId
                          correlationId:self.correlationId
                        completionBlock:^(ServiceInformation *svcInfo, NSError *error)
     {
         
         if(error)
         {
             AD_LOG_ERROR(@"WPJ discovery failed", error.code, nil);
             onResultBlock(error);
             return;
         }
         
         AD_LOG_INFO(@"WPJ discovery succeeded. Acquiring token for broker client id and DRS resource", nil);
         //find an access token or refresh token for the UPN.
         [self acquireAccount:[svcInfo oauthAuthCodeEndpoint]
                       userId:identifier
                     clientId:BROKER_CLIENT_ID
                     resource:[svcInfo registrationResourceId]
                  redirectUri:BROKER_REDIRECT_URI
         extraQueryParameters:@"nux=1"
                       appKey:DEFAULT_GUID_FOR_NIL
                        force:NO
              completionBlock:^(ADAuthenticationResult *result) {
                  if(result.status == AD_SUCCEEDED)
                  {
                      AD_LOG_INFO(@"acquireToken for broker client id and DRS resource succeeded", nil);
                      [workPlaceJoinApi registerDeviceForUser:identifier.userId
                                                        token:result.accessToken
                                         registrationEndpoint:[svcInfo registrationEndpoint]
                                   registrationServiceVersion:[svcInfo registrationServiceVersion]
                                                correlationId:self.correlationId
                                              completionBlock:^(NSError *error)
                      {
                          if(!error)
                          {
                              AD_LOG_INFO(@"WPJ device registration succeeded.", nil);
                              [self acquirePRTForIdentifier:identifier
                                         serviceInformation:svcInfo
                                              onResultBlock:onResultBlock];
							  return;
                          }
                          else
                          {
                              AD_LOG_ERROR_F(@"WPJ request FAILED", error.code, error.description, nil);
                              onResultBlock(error);
                              return;
                          }
                      }];
					  return;
                  }
                  else
                  {
                      AD_LOG_ERROR_F(@"acquireToken for broker client id and DRS resource FAILED", result.error.code, result.error.description, nil);
                      onResultBlock(result.error);
                      return;
                  }
              }];
         
     }];
}

- (void)acquirePRTForIdentifier:(ADUserIdentifier*)identifier
             serviceInformation:(ServiceInformation*)svcInfo
                  onResultBlock:(WPJCallback)onResultBlock
{
    [self acquirePRTForIdentifier:identifier
               serviceInformation:svcInfo
                      allowSilent:YES
                    onResultBlock:onResultBlock];
}

- (void)acquirePRTForIdentifier:(ADUserIdentifier*)identifier
             serviceInformation:(ServiceInformation*)svcInfo
                    allowSilent:(BOOL)allowSilent
                  onResultBlock:(WPJCallback)onResultBlock
{
    AD_LOG_INFO(@"Attempting to get Primary Refresh Token", nil);
    
    ADAuthenticationError* error;
    //do PRT work
    ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc] initWithIdentifier:identifier
                                                                      authority:[svcInfo oauthAuthCodeEndpoint]
                                                                  correlationId:self.correlationId
                                                                          error:&error];
    if (!prtCtx)
    {
        onResultBlock(error);
        return;
    }
    
    if (!_initialAttemptTime)
    {
        _initialAttemptTime = [NSDate date];
    }
    
    [prtCtx acquirePRTForUPN:allowSilent
                    callback:^(ADBrokerPRTCacheItem *item, NSError *error)
     {
         if(!error)
         {
             AD_LOG_INFO(@"Primary Refresh Token acquired successfully.", nil);
             _initialAttemptTime = nil;
             onResultBlock(error);
             return;
         }
         
         ++_wpjRetryAttempt;
         if ([_initialAttemptTime timeIntervalSinceNow] < -[[ADBrokerSettings sharedInstance] prtRetryTimeout])
         {
             AD_LOG_ERROR_F(@"PRT Acquisition Timedout", error.code, @"Failed after %d attempts. (%@) Timeout reached.", _wpjRetryAttempt, error.description);
             _initialAttemptTime = nil;
             onResultBlock(error);
             return;
         }
         
         AD_LOG_ERROR_F(@"PRT Acquisition Failed, Retrying.", error.code, @"Request attempt %d failed. (%@) Attempting again in 5.0 seconds...", _wpjRetryAttempt, error.description);
         [NSThread sleepForTimeInterval:5.0];
         
         [self acquirePRTForIdentifier:identifier
              serviceInformation:svcInfo
                           allowSilent:NO
                   onResultBlock:onResultBlock];
     }];
}

-(BOOL) isWorkplaceJoined:(NSString*) upn
{
    API_ENTRY;
    RegistrationInformation* regInfo = [ADBrokerContext getWorkPlaceJoinInformation];
    BOOL result = NO;
    if(regInfo)
    {
        result = [NSString adSame:[upn lowercaseString] toString:[[regInfo userPrincipalName] lowercaseString]];
    }
    return result;
}

+ (RegistrationInformation*) getWorkPlaceJoinInformation
{
    return [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:nil];
}


- (void) removeWorkPlaceJoinRegistration:(ADOnResultCallback) onResultBlock
{
    API_ENTRY;
    RegistrationInformation* regInfo = [ADBrokerContext getWorkPlaceJoinInformation];
    if (!regInfo)
    {
        AD_LOG_ERROR(@"No WPJ registration to remove!", AD_FAILED, 0);
        onResultBlock(nil);
        return;
    }
    
    __block NSString* upn = regInfo.userPrincipalName;
    //remove WPJ as well
    [ [WorkPlaceJoin WorkPlaceJoinManager] leaveWithCorrelationId:self.correlationId
                                                  completionBlock:^(NSError *error)
     {
         ADBrokerPRTContext* brokerCtx = [[ADBrokerPRTContext alloc] initWithIdentifier:[ADUserIdentifier identifierWithId:upn]
                                                                              authority:nil
                                                                          correlationId:self.correlationId
                                                                                  error:nil];
         [brokerCtx deletePRT];
         onResultBlock(error);
     }];
}


- (void) removeAccount: (NSString*) upn
         onResultBlock:(ADOnResultCallback) onResultBlock
{
    API_ENTRY;
    RegistrationInformation* regInfo = [ADBrokerContext getWorkPlaceJoinInformation];
    
    NSHTTPCookieStorage* storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = [storage cookies];
    for (NSHTTPCookie* cookie in cookies)
    {
        [storage deleteCookie:cookie];
    }
    
    if(regInfo && [NSString adSame:[upn lowercaseString] toString:[regInfo.userPrincipalName lowercaseString]])
    {
        //remove WPJ as well
        [ self removeWorkPlaceJoinRegistration:^(NSError *error) {
            //do nothing
            [self deleteFromCache:[ADBrokerKeychainTokenCacheStore new]
                              upn:upn];
            onResultBlock(error);
        }];
        
        regInfo = nil;
    }
    else
    {
        [self deleteFromCache:[ADBrokerKeychainTokenCacheStore new]
                          upn:upn];
        onResultBlock(nil);
    }
    
}

-(void) deleteFromCache:(id<ADTokenCacheStoring>) cache
                    upn:(NSString*) upn
{
    ADAuthenticationError* error;
    [cache removeAllForUser:upn error:&error];
}

-(void) addRefreshTokenTo:(ADAuthenticationResult*) result
                fromCache:(id<ADTokenCacheStoring>) cache
{
    if(!result.tokenCacheStoreItem.refreshToken)
    {
        ADTokenCacheStoreItem* item = [result.tokenCacheStoreItem copy];
        item.resource = nil;
        ADTokenCacheStoreItem* rtItem = [cache getItemWithKey:[item extractKeyWithError:nil]
                                                       userId:result.tokenCacheStoreItem.userInformation.upn
                                                        error:nil];
        if(rtItem)
        {
            result.tokenCacheStoreItem.refreshToken = rtItem.refreshToken;
        }
    }
}

@end


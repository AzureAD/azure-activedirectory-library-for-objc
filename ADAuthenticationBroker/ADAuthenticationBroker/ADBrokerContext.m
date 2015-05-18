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

@interface ADAuthenticationContext ()

- (void)internalAcquireTokenWithResource:(NSString*)resource
                                clientId:(NSString*)clientId
                             redirectUri:(NSURL*)redirectUri
                          promptBehavior:(ADPromptBehavior)promptBehavior
                                  silent:(BOOL)silent /* Do not show web UI for authorization. */
                                  userId:(NSString*)userId
                                   scope:(NSString*)scope
                    extraQueryParameters:(NSString*)queryParams
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock;

- (void) requestTokenWithResource: (NSString*) resource
                         clientId: (NSString*) clientId
                      redirectUri: (NSURL*) redirectUri
                   promptBehavior: (ADPromptBehavior) promptBehavior
                           silent: (BOOL) silent /* Do not show web UI for authorization. */
                           userId: (NSString*) userId
                            scope: (NSString*) scope
             extraQueryParameters: (NSString*) queryParams
                    correlationId: (NSUUID*) correlationId
                  completionBlock: (ADAuthenticationCallback)completionBlock;

@end

@implementation ADBrokerContext

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG) \
if (![self checkAndHandleBadArgument:ARG \
argumentName:TO_NSSTRING(#ARG) \
completionBlock:completionBlock]) \
{ \
return; \
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
    BOOL isBrokerRequest = requestPayloadUrl && [[requestPayloadUrl host] isEqualToString:@"broker"];
    *returnUpn = nil;
    if(isBrokerRequest)
    {
        NSArray * parts = [[requestPayloadUrl absoluteString] componentsSeparatedByString:@"?"];
        NSString *qp = [parts objectAtIndex:1];
        NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
        if(![NSString adIsStringNilOrBlank:[queryParamsMap valueForKey:USERNAME]])
        {
            *returnUpn = [queryParamsMap valueForKey:USERNAME];
        }
    }
    
    return isBrokerRequest;
}



+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
{
    API_ENTRY;
    [ADBrokerContext invokeBrokerForSourceApplication:requestPayload
                                    sourceApplication:sourceApplication
                                                  upn:nil];
}

+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
                                      upn: (NSString*) upn
{
    API_ENTRY;
    
    ADAuthenticationError* error = nil;
    
    NSArray * parts = [requestPayload componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];

    THROW_ON_NIL_ARGUMENT(requestPayload);
    THROW_ON_NIL_ARGUMENT(sourceApplication);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:AUTHORITY]);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:OAUTH2_CLIENT_ID]);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:BROKER_KEY]);
    THROW_ON_NIL_ARGUMENT([queryParamsMap valueForKey:CLIENT_ADAL_VERSION]);
    
    if(!error)
    {
        //validate source application against redirect uri
        NSURL *redirectUri = [[NSURL alloc] initWithString:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]];
        if(![NSString adSame:sourceApplication toString:[redirectUri host]]){
            
            error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_ARGUMENT
                                                           protocolCode:nil
                                                           errorDetails:@"source application bundle identifier should be same as the redirect URI domain"];
            
            NSString* response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@",
                                   [error.protocolCode adUrlFormEncode],
                                   [error.errorDetails adUrlFormEncode],
                                   [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
            [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI] response:response];
            return;
        }
        
        [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
        ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:AUTHORITY];
        
        //update version after creating ADBrokerContext instance because the instance creation
        //sets the client ADAL version to 0.0.0
        [ADLogger setAdalVersion:[queryParamsMap valueForKey:CLIENT_ADAL_VERSION]];
        ctx.correlationId = [[NSUUID alloc]
                             initWithUUIDString:[queryParamsMap
                                                 valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
        if(ctx)
        {
            ADAuthenticationCallback takeMeBack = ^(ADAuthenticationResult *result)
            {
                if(![NSString adSame:sourceApplication toString:DEFAULT_GUID_FOR_NIL])
                {
                    NSString* response = nil;
                    if(result.status == AD_SUCCEEDED){
                        NSString* rawIdToken = @"";
                        if(result.tokenCacheStoreItem.userInformation){
                            rawIdToken = result.tokenCacheStoreItem.userInformation.rawIdToken;
                        }
                        
                        response = [NSString stringWithFormat:@"authority=%@&client_id=%@&resource=%@&user_id=%@&correlation_id=%@&access_token=%@&refresh_token=%@&id_token=%@",
                                    [queryParamsMap valueForKey:AUTHORITY],
                                    [queryParamsMap valueForKey:OAUTH2_CLIENT_ID],
                                    [queryParamsMap valueForKey:OAUTH2_RESOURCE],
                                    upn,
                                    [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE],
                                    result.accessToken,
                                    result.tokenCacheStoreItem.refreshToken,
                                    rawIdToken];
                        
                        NSString* brokerKey = [queryParamsMap valueForKey:BROKER_KEY];
                        NSData *decodedKey = [NSString Base64DecodeData:brokerKey];
                        NSString *decodedKeyString = [[NSString alloc] initWithData:decodedKey encoding:0];
                        
                        NSData *plainData = [response dataUsingEncoding:NSUTF8StringEncoding];
                        NSData* responseData = [ADBrokerHelpers encryptData:plainData key:decodedKeyString];
                        
                        response = [NSString stringWithFormat:@"response=%@&hash=%@", [[NSString Base64EncodeData: responseData] adUrlFormEncode], [ADBrokerHelpers computeHash:plainData]];
                    } else{
                        response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@", [result.error.protocolCode adUrlFormEncode], [result.error.errorDetails adUrlFormEncode], [queryParamsMap valueForKey:OAUTH2_CORRELATION_ID_RESPONSE]];
                    }
                    
                    [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI] response:response];
                    return;
                }
            };
            
            NSString* extraQP =[queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS];
            NSDictionary* extraQpDictionary = [NSDictionary adURLFormDecode:extraQP];
            extraQP = nil;
            if([extraQpDictionary valueForKey:@"mamver"])
            {
                extraQP = [NSString stringWithFormat:@"mamver=%@", [extraQpDictionary valueForKey:@"mamver"]];
            }
            
            [ctx acquireAccount:[queryParamsMap valueForKey:AUTHORITY]
                         userId:upn
                       clientId:[queryParamsMap valueForKey:OAUTH2_CLIENT_ID]
                       resource:[queryParamsMap valueForKey:OAUTH2_RESOURCE]
                    redirectUri:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]
           extraQueryParameters:extraQP
                         appKey:[queryParamsMap valueForKey:BROKER_KEY]
                completionBlock:^(ADAuthenticationResult *result) {
                    
                    if(result.status != AD_SUCCEEDED && result.error.code == AD_ERROR_WPJ_REQUIRED)
                    {
                        ADAuthenticationError* err = result.error;
                        [ctx doWorkPlaceJoinForUpn:[err.userInfo valueForKey:@"username"]
                                     onResultBlock:^(NSError *error) {
                                         if(!error)
                                         {
                                             [ctx acquireAccount:[queryParamsMap valueForKey:AUTHORITY]
                                                          userId:[err.userInfo valueForKey:@"username"]
                                                        clientId:[queryParamsMap valueForKey:OAUTH2_CLIENT_ID]
                                                        resource:[queryParamsMap valueForKey:OAUTH2_RESOURCE]
                                                     redirectUri:[queryParamsMap valueForKey:OAUTH2_REDIRECT_URI]
                                            extraQueryParameters:extraQP
                                                          appKey:[queryParamsMap valueForKey:BROKER_KEY]
                                                 completionBlock:takeMeBack];
                                         }
                                         else
                                         {
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
        }
    }
}

+(void)openAppInBackground:(NSString *)application
                  response:(NSString *)response
{
    NSURL* appUrl = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@/broker?%@", application, response]];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] openURL:appUrl];
    });
}


+ (NSArray*) getAllAccounts:(ADAuthenticationError*) error
{
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
                                           errorDetails:nil];
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
            [users addObject:user.userId];
            [accountsArray addObject:[[ADBrokerUserAccount alloc] init:user
                                                     isWorkplaceJoined:[NSString adSame:user.userId
                                                                               toString:wpjUpn]
                                                          isNGCEnabled:NO]];
        }
    }
    
    return accountsArray;
}


- (void) acquireAccount:(NSString*) authority
                 userId:(NSString*) upn
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
   extraQueryParameters:(NSString*) queryParams
                 appKey:(NSString*) appKey
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
    BOOL forceUI = [NSString adIsStringNilOrBlank:upn];
    
    NSString* qp = [NSString stringWithFormat:@"%@&%@", @"brkr=1", queryParams];
    
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
            if([self isWorkplaceJoined:upn])
            {
                AD_LOG_INFO(@"acquireAccount - FAILED", @"Workplace joined = true. Attempt to get token using PRT");
                ADAuthenticationError* error = nil;
                ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc] initWithUpn:upn
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
                if(![NSString adIsStringNilOrBlank:upn])
                {AD_LOG_INFO(@"acquireAccount - FAILED", @"Workplace joined = FALSE. UPN was provided and silent cache lookup failed. Get a new token via UI.");
                    [ctx requestTokenWithResource:resource
                                                 clientId:clientId
                                              redirectUri:[NSURL URLWithString:redirectUri]
                                           promptBehavior:AD_PROMPT_AUTO
                                                   silent:NO
                                                   userId:upn
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
                                       userId:upn
                                        scope:nil
                         extraQueryParameters:@"brkr=1"
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
                                     userId:upn
                            completionBlock:defaultCallback];
    }
    
}


- (void) acquireAccount:(NSString*) upn
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireAccount:_authority
                  userId:upn
                clientId:BROKER_CLIENT_ID
                resource:BROKER_RESOURCE
             redirectUri:BROKER_REDIRECT_URI
    extraQueryParameters:nil
                  appKey:DEFAULT_GUID_FOR_NIL
         completionBlock:completionBlock];
}


// to be used when user invokes add account flow from the app
- (void) acquireAccount:(NSString*) upn
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireAccount:_authority
                  userId:upn
                clientId:clientId
                resource:resource
             redirectUri:redirectUri
    extraQueryParameters:nil
                  appKey:DEFAULT_GUID_FOR_NIL
         completionBlock:completionBlock];
}

- (void) doWorkPlaceJoinForUpn: (NSString*) upn
                 onResultBlock:(WPJCallback) onResultBlock
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
    
    [workPlaceJoinApi doDiscoveryForUpn:upn
                          correlationId:self.correlationId
                        completionBlock:^(ServiceInformation *svcInfo, NSError *error)
     {
         
         if(error)
         {
             onResultBlock(error);
             return;
         }
         
         //find an access token or refresh token for the UPN.
         [self acquireAccount:[svcInfo oauthAuthCodeEndpoint]
                       userId:upn
                     clientId:BROKER_CLIENT_ID
                     resource:[svcInfo registrationResourceId]
                  redirectUri:BROKER_REDIRECT_URI
         extraQueryParameters:nil
                       appKey:DEFAULT_GUID_FOR_NIL
              completionBlock:^(ADAuthenticationResult *result) {
                  if(result.status == AD_SUCCEEDED)
                  {
                      [workPlaceJoinApi registerDeviceForUser:upn
                                                        token:result.accessToken
                                         registrationEndpoint:[svcInfo registrationEndpoint]
                                   registrationServiceVersion:[svcInfo registrationServiceVersion]
                                                correlationId:self.correlationId
                                              completionBlock:^(NSError *error) {
                                                  if(!error)
                                                  {
                                                      //do PRT work
                                                      ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc]
                                                                                    initWithUpn:upn
                                                                                    correlationId:self.correlationId
                                                                                    error:&error];
                                                      [prtCtx acquirePRTForUPN:^(ADBrokerPRTCacheItem *item, NSError *error) {
                                                          if(error)
                                                          {
                                                              ADBrokerPRTContext* newCtx = [[ADBrokerPRTContext alloc]
                                                                                            initWithUpn:upn
                                                                correlationId:self.correlationId
                                                                                            error:&error];
                                                              
                                                              [NSThread sleepForTimeInterval:[ADBrokerSettings sharedInstance].prtRequestWaitInSeconds];
                                                              [newCtx acquirePRTForUPN:^(ADBrokerPRTCacheItem *item, NSError *error){
                                                                  onResultBlock(error);
                                                              }];
                                                              return;
                                                          }
                                                          else
                                                          {
                                                              onResultBlock(error);
                                                              return;
                                                          }
                                                      }];
                                                  }
                                                  else
                                                  {
                                                      onResultBlock(error);
                                                      return;
                                                  }
                                              }];
                  }
                  else
                  {
                      onResultBlock(result.error);
                      return;
                  }
              }];
         
     }];
}

-(BOOL) isWorkplaceJoined:(NSString*) upn
{
    API_ENTRY;
    RegistrationInformation* regInfo = [ADBrokerContext getWorkPlaceJoinInformation];
    BOOL result = NO;
    if(regInfo)
    {
        result = [NSString adSame:upn toString:[regInfo userPrincipalName]];
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
    NSString* upn = regInfo.userPrincipalName;
    if(regInfo)
    {
        //remove WPJ as well
        [ [WorkPlaceJoin WorkPlaceJoinManager] leaveWithCorrelationId:self.correlationId
                                                        completionBlock:^(NSError *error)
         {
             ADBrokerPRTContext* brokerCtx = [[ADBrokerPRTContext alloc] initWithUpn:upn
                                                                       correlationId:self.correlationId
                                                                               error:nil];
             [brokerCtx deletePRT];
         }];
        
        regInfo = nil;
    }
}


- (void) removeAccount: (NSString*) upn
         onResultBlock:(ADOnResultCallback) onResultBlock
{
    API_ENTRY;
    RegistrationInformation* regInfo = [ADBrokerContext getWorkPlaceJoinInformation];
    if(regInfo && [NSString adSame:upn toString:regInfo.userPrincipalName])
    {
        //remove WPJ as well
        [ self removeWorkPlaceJoinRegistration:^(NSError *error) {
            //do nothing
        }];
        
        regInfo = nil;
    }
    
    [self deleteFromCache:[ADBrokerKeychainTokenCacheStore new]
                      upn:upn];
    onResultBlock(nil);
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
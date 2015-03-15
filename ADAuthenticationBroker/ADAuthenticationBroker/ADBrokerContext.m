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
#import <ADALiOS/ADAuthenticationSettings.h>
#import <workplaceJoinAPI/WorkPlaceJoin.h>
#import "ADBrokerContext.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADBrokerConstants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import "ADBrokerHelpers.h"
#import "ADBrokerPRTCacheItem.h"
#import "ADBrokerUserAccount.h"

@implementation ADBrokerContext

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG) \
if (![self checkAndHandleBadArgument:ARG \
argumentName:TO_NSSTRING(#ARG) \
completionBlock:completionBlock]) \
{ \
return; \
}

- (id) initWithAuthority:(NSString*) authority
{
    self = [super init];
    if(self)
    {
        _authority = authority;
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
    
    BOOL isBrokerRequest = requestPayloadUrl && [[requestPayloadUrl host] isEqualToString:@"broker"];
    if(isBrokerRequest)
    {
        NSArray * parts = [[requestPayloadUrl absoluteString] componentsSeparatedByString:@"?"];
        NSString *qp = [parts objectAtIndex:1];
        NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
        *returnUpn = [queryParamsMap valueForKey:USER_ID];
    }
    
    return isBrokerRequest;
}



+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication                          completionBlock: (ADAuthenticationCallback) completionBlock
{
    [ADBrokerContext invokeBrokerForSourceApplication:requestPayload
                                    sourceApplication:sourceApplication
                                                  upn:nil
                                      completionBlock:completionBlock];
}

+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
                                      upn: (NSString*) upn
                          completionBlock: (ADAuthenticationCallback) completionBlock
{
//    if([NSString adSame:sourceApplication toString:DEFAULT_GUID_FOR_NIL])
//    {
//        THROW_ON_NIL_ARGUMENT(completionBlock);
//    }
    
    HANDLE_ARGUMENT(requestPayload);
    HANDLE_ARGUMENT(sourceApplication);
    
    NSArray * parts = [requestPayload componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    
    HANDLE_ARGUMENT([queryParamsMap valueForKey:AUTHORITY]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:CLIENT_ID]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:CORRELATION_ID]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:REDIRECT_URI]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:BROKER_KEY]);
    
    //validate source application against redirect uri
    ADAuthenticationError* error = nil;
    NSURL *redirectUri = [[NSURL alloc] initWithString:[queryParamsMap valueForKey:REDIRECT_URI]];
    if(![NSString adSame:sourceApplication toString:[redirectUri host]]){
        //TODO - get right error
        error = [ADAuthenticationError errorFromNSError:nil errorDetails:@"source application bundle identifier should be same as the redirect URI domain"];
    }
    
    if(!error)
    {
        [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
        ADBrokerContext* ctx = [ADBrokerContext new];
        ctx.correlationId = [[NSUUID alloc]
                             initWithUUIDString:[queryParamsMap
                                                 valueForKey:CORRELATION_ID]];
        if(ctx)
        {
            NSString* extraQp = nil;
            if([queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS])
            {
                extraQp = [queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS];
            }
            
            ADAuthenticationCallback defaultCallback = ^(ADAuthenticationResult *result)
            {
                if([NSString adSame:sourceApplication toString:DEFAULT_GUID_FOR_NIL])
                {
                    completionBlock(result);
                }
                else
                {
                    NSString* response = nil;
                    if(result.status == AD_SUCCEEDED){
                        NSString* rawIdToken = @"";
                        if(result.tokenCacheStoreItem.userInformation){
                            rawIdToken = result.tokenCacheStoreItem.userInformation.rawIdToken;
                        }
                        
                        response = [NSString stringWithFormat:@"authority=%@&client_id=%@&resource=%@&correlation_id=%@&access_token=%@&id_token=%@", [queryParamsMap valueForKey:AUTHORITY], [queryParamsMap valueForKey:CLIENT_ID], [queryParamsMap valueForKey:RESOURCE], [queryParamsMap valueForKey:CORRELATION_ID], result.accessToken, rawIdToken];
                        
                        NSString* brokerKey = [queryParamsMap valueForKey:BROKER_KEY];
                        NSData *decodedKey = [NSString Base64DecodeData:brokerKey];
                        NSString *decodedKeyString = [[NSString alloc] initWithData:decodedKey encoding:0];
                        
                        NSData *plainData = [response dataUsingEncoding:NSUTF8StringEncoding];
                        NSData* responseData = [ADBrokerHelpers encryptData:plainData key:decodedKeyString];
                        
                        response = [NSString stringWithFormat:@"response=%@&hash=%@", [[NSString Base64EncodeData: responseData] adUrlFormEncode], [ADBrokerHelpers computeHash:plainData]];
                    } else{
                        response =  [NSString stringWithFormat:@"code=%@&error_description=%@&correlation_id=%@", [result.error.protocolCode adUrlFormEncode], [result.error.errorDetails adUrlFormEncode], [queryParamsMap valueForKey:CORRELATION_ID]];
                    }
                    
                    [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:REDIRECT_URI] response:response];
                }
            };
            
            
            [ctx acquireAccount:[queryParamsMap valueForKey:AUTHORITY]
                         userId:[queryParamsMap valueForKey:USER_ID]
                       clientId:[queryParamsMap valueForKey:CLIENT_ID]
                       resource:[queryParamsMap valueForKey:RESOURCE]
                    redirectUri:[queryParamsMap valueForKey:REDIRECT_URI]
                         appKey:[queryParamsMap valueForKey:BROKER_KEY]
                completionBlock:defaultCallback];
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
        [regInfo releaseData];
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
    
    cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    array = [cache allItemsWithError:&error];
    if (error)
    {
        return accountsArray;
    }
    
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
                 appKey:(NSString*) appKey
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    ADAuthenticationError* error = nil;
    [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
    //if client id is not broker, use incoming app's key for cache.
    ADAuthenticationContextForBroker* ctx = [[ADAuthenticationContextForBroker alloc]
                                             initWithAuthority:authority
                                             validateAuthority:YES
                                             tokenCacheStore:[[ADBrokerKeychainTokenCacheStore alloc]initWithAppKey:appKey]
                                             error:&error];
    [ctx setCorrelationId:_correlationId];
    
    // if UPN is blank, do not use acquire token silent as it will return
    // the default token in the case in case there is a single user.
    
    BOOL forceUI = [NSString adIsStringNilOrBlank:upn];
    
    ADAuthenticationCallback defaultCallback = ^(ADAuthenticationResult *result) {
        //if failed, check for and use PRT
        if(result.status == AD_SUCCEEDED)
        {
            //update first party cache
            if(![NSString adSame:clientId toString: BROKER_CLIENT_ID])
            {
                id<ADTokenCacheStoring> firstPartyCache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
                //save AT and RT in the cache
                [ctx updateCacheToResult:result
                           cacheInstance:firstPartyCache
                               cacheItem:nil
                        withRefreshToken:nil];
                result = [ctx updateResult:result
                                    toUser:upn];
            }
            
            completionBlock(result);
            return;
        }
        else
        {
            //silent call failed. check if the user is WPJ.
            if([self isWorkplaceJoined:upn])
            {
                ADAuthenticationError* error = nil;
                ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc] initWithUpn:upn
                                                                       correlationId:_correlationId
                                                                               error:&error];
                [prtCtx acquireTokenUsingPRTForResource:resource
                                               clientId:clientId
                                            redirectUri:redirectUri
                                                 appKey:appKey
                                        completionBlock:completionBlock];
            }
            else
            { //not WPJ. Simply call AT
                if(!forceUI){
                [ctx acquireTokenWithResource:resource
                                     clientId:clientId
                                  redirectUri:[NSURL URLWithString:redirectUri]
                                       userId:upn
                         extraQueryParameters:@"nux=1"
                              completionBlock:completionBlock];
                } else {
                    completionBlock(result);
                    return;
                }
            }
        }
    };
    
    if(!forceUI)
    {
    //silent call also does the AT refresh, if needed.
    [ctx acquireTokenSilentWithResource: resource
                         clientId: clientId
                      redirectUri: [NSURL URLWithString:redirectUri]
                           userId: upn
                  completionBlock:defaultCallback];
    }
    else
    {
        [ctx acquireTokenWithResource:resource
                             clientId:clientId
                          redirectUri:[NSURL URLWithString:redirectUri]
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:upn
                 extraQueryParameters:@"nux=1"
                      completionBlock:completionBlock];
    }
}

// to be used when user invokes add account flow from the app
- (void) acquireAccount:(NSString*) upn
               clientId:(NSString*) clientId
               resource:(NSString*) resource
            redirectUri:(NSString*) redirectUri
        completionBlock:(ADAuthenticationCallback) completionBlock
{
    [self acquireAccount:_authority
                  userId:upn
                clientId:clientId
                resource:resource
             redirectUri:redirectUri
                  appKey:DEFAULT_GUID_FOR_NIL
         completionBlock:completionBlock];
}

- (void) doWorkPlaceJoinForUpn: (NSString*) upn
                 onResultBlock:(ADPRTResultCallback) onResultBlock
{
    
    WorkPlaceJoin *workPlaceJoinApi = [WorkPlaceJoin WorkPlaceJoinManager];
    NSError* error;
    ServiceInformation *svcInfo = [workPlaceJoinApi doDiscoveryForUpn:upn error:&error];
    [svcInfo registrationEndpoint];
    
    //find an access token or refresh token for the UPN.
    [self acquireAccount:[svcInfo registrationEndpoint]
                  userId:upn
                clientId:BROKER_CLIENT_ID
                resource:[svcInfo registrationResourceId]
             redirectUri:BROKER_REDIRECT_URI
                  appKey:DEFAULT_GUID_FOR_NIL
         completionBlock:^(ADAuthenticationResult *result) {
             if(result.status == AD_SUCCEEDED)
             {
                 [workPlaceJoinApi registerDeviceForUser:upn
                                                   token:result.accessToken
                                         completionBlock:^(NSError *error) {
                                             if(!error)
                                             {
                                                 //do PRT work
                                                 ADBrokerPRTContext* prtCtx = [[ADBrokerPRTContext alloc]
                                                                               initWithUpn:upn
                                                                               correlationId:nil
                                                                               error:&error];
                                                 [prtCtx acquirePRTForUPN:onResultBlock];
                                             } else {
                                                 onResultBlock(nil, error);
                                             }
                                         }];
             }
             else
             {
                 onResultBlock(nil, result.error);
             }
         }];
}

-(BOOL) isWorkplaceJoined:(NSString*) upn
{
    RegistrationInformation* regInfo = [self getWorkPlaceJoinInformation];
    BOOL result = NO;
    if(regInfo)
    {
        result = [NSString adSame:upn toString:[regInfo userPrincipalName]];
        [regInfo releaseData];
    }
    return result;
}

- (RegistrationInformation*) getWorkPlaceJoinInformation
{
    return [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation:nil];
}


- (void) removeWorkPlaceJoinRegistration:(ADOnResultCallback) onResultBlock
{
    [[WorkPlaceJoin WorkPlaceJoinManager] leaveWithCompletionBlock:onResultBlock];
}


- (void) removeAccount: (NSString*) upn
         onResultBlock:(ADOnResultCallback) onResultBlock
{
    RegistrationInformation* regInfo = [self getWorkPlaceJoinInformation];
    if(regInfo && [NSString adSame:upn toString:regInfo.userPrincipalName])
    {
        //remove WPJ as well
        [ self removeWorkPlaceJoinRegistration:nil];
        [regInfo releaseData];
        regInfo = nil;
    }
    
    
    
}

@end
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

#import "ADAuthenticationContext+Internal.h"
#import "ADAuthenticationSettings.h"
#import "ADBrokerKeyHelper.h"
#import "ADBrokerNotificationManager.h"
#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"
#import "ADPkeyAuthHelper.h"
#import "ADHelpers.h"

@implementation ADAuthenticationContext (Broker)

+ (BOOL)canUseBroker
{
    return [[ADAuthenticationSettings sharedInstance] credentialsType] == AD_CREDENTIALS_AUTO &&
    [[UIApplication sharedApplication] canOpenURL:[[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker", brokerScheme]]];
}

+ (BOOL) respondsToUrl:(NSString*)url
{
    BOOL schemeIsInPlist = NO; // find out if the sceme is in the plist file.
    NSBundle* mainBundle = [NSBundle mainBundle];
    NSArray* cfBundleURLTypes = [mainBundle objectForInfoDictionaryKey:@"CFBundleURLTypes"];
    if ([cfBundleURLTypes isKindOfClass:[NSArray class]] && [cfBundleURLTypes lastObject]) {
        NSDictionary* cfBundleURLTypes0 = [cfBundleURLTypes objectAtIndex:0];
        if ([cfBundleURLTypes0 isKindOfClass:[NSDictionary class]]) {
            NSArray* cfBundleURLSchemes = [cfBundleURLTypes0 objectForKey:@"CFBundleURLSchemes"];
            if ([cfBundleURLSchemes isKindOfClass:[NSArray class]]) {
                for (NSString* scheme in cfBundleURLSchemes) {
                    if ([scheme isKindOfClass:[NSString class]] && [url hasPrefix:scheme]) {
                        schemeIsInPlist = YES;
                        break;
                    }
                }
            }
        }
    }
    
    BOOL canOpenUrl = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString: url]];
    
    return schemeIsInPlist && canOpenUrl;
}

+ (void)internalHandleBrokerResponse:(NSURL *)response
{
    THROW_ON_NIL_ARGUMENT([ADBrokerNotificationManager sharedInstance].callbackForBroker);
    ADAuthenticationCallback completionBlock = [ADBrokerNotificationManager sharedInstance].callbackForBroker;
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
        HANDLE_ARGUMENT([queryParamsMap valueForKey:BROKER_HASH_KEY]);
        
        NSString* hash = [queryParamsMap valueForKey:BROKER_HASH_KEY];
        NSString* encryptedBase64Response = [queryParamsMap valueForKey:BROKER_RESPONSE_KEY];
        
        //decrypt response first
        ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] initHelper];
        ADAuthenticationError* error;
        NSData *encryptedResponse = [NSString Base64DecodeData:encryptedBase64Response ];
        NSData* decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse error:&error];
        NSString* decryptedString = nil;
        
        if(!error)
        {
            decryptedString =[[NSString alloc] initWithData:decrypted encoding:0];
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
                                                                                            errorDetails:@"Decrypted response does not match the hash"]];
            }
        }
        else
        {
            result = [ADAuthenticationResult resultFromError:error];
        }
    }
    
    if (AD_SUCCEEDED == result.status)
    {
        result.tokenCacheStoreItem.accessTokenType = @"Bearer";
        // Token response
        id expires_on = [queryParamsMap objectForKey:@"expires_on"];
        NSDate *expires    = nil;
        if ( expires_on != nil )
        {
            if ( [expires_on isKindOfClass:[NSString class]] )
            {
                NSNumberFormatter *formatter = [[NSNumberFormatter alloc] init];
                
                expires = [NSDate dateWithTimeIntervalSince1970:[formatter numberFromString:expires_on].longValue];
            }
            else if ( [expires_on isKindOfClass:[NSNumber class]] )
            {
                expires = [NSDate dateWithTimeIntervalSince1970:((NSNumber *)expires_on).longValue];
            }
            else
            {
                AD_LOG_WARN_F(@"Unparsable time", @"The response value for the access token expiration cannot be parsed: %@", expires);
                // Unparseable, use default value
                expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//1 hour
            }
        }
        else
        {
            AD_LOG_WARN(@"Missing expiration time.", @"The server did not return the expiration time for the access token.");
            expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];//Assume 1hr expiration
        }
        
        result.tokenCacheStoreItem.expiresOn = expires;
        ADAuthenticationContext* ctx = [ADAuthenticationContext
                                        authenticationContextWithAuthority:result.tokenCacheStoreItem.authority
                                        error:nil];
        
        SEL selector = @selector(updateCacheToResult:cacheItem:withRefreshToken:);
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:[ctx methodSignatureForSelector:selector]];
        [inv setSelector:selector];
        [inv setTarget:ctx];
        [inv setArgument:&result atIndex:2];
        [inv invoke];
        
        NSString* userId = [queryParamsMap valueForKey:@"user_id"];
        selector = nil;
        selector = @selector(updateResult:toUser:);
        inv = nil;
        inv = [NSInvocation invocationWithMethodSignature:[ctx methodSignatureForSelector:selector]];
        [inv setSelector:selector];
        [inv setTarget:ctx];
        [inv setArgument:&result atIndex:2];
        if(userId)
        {
            [inv setArgument:&userId atIndex:3];
        }
        
        [inv invoke];
    }
    
    completionBlock(result);
    [ADBrokerNotificationManager sharedInstance].callbackForBroker = nil;
}

- (void)callBrokerForAuthority:(NSString*)authority
                      resource:(NSString*)resource
                      clientId:(NSString*)clientId
                   redirectUri:(NSURL*)redirectUri
                        userId:(NSString*)userId
          extraQueryParameters:(NSString*)queryParams
                 correlationId:(NSString*)correlationId
               completionBlock:(ADAuthenticationCallback)completionBlock

{
    ADAuthenticationError* error = nil;
    if(![ADAuthenticationContext respondsToUrl:[redirectUri absoluteString]])
    {
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_REDIRECT_URI
                                                       protocolCode:nil
                                                       errorDetails:ADRedirectUriInvalidError];
        completionBlock([ADAuthenticationResult resultFromError:error]);
        return;
    }
    
    AD_LOG_INFO(@"Invoking broker for authentication", nil);
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] initHelper];
    NSData* key = [brokerHelper getBrokerKey:&error];
    NSString* base64Key = [NSString Base64EncodeData:key];
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    
    NSDictionary* queryDictionary = @{
                                      @"authority": authority,
                                      @"resource" : resource,
                                      @"client_id": clientId,
                                      @"redirect_uri": redirectUri.absoluteString,
                                      @"username": userId,
                                      @"correlation_id": correlationId,
                                      @"broker_key": base64UrlKey,
                                      @"client_version": [ADLogger getAdalVersion],
                                      @"extra_qp": queryParams,
                                      };
    
    NSString* query = [queryDictionary adURLFormEncode];
    
    NSURL* appUrl = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://broker?%@", brokerScheme, query]];
    
    [[ADBrokerNotificationManager sharedInstance] enableOnActiveNotification:completionBlock];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] openURL:appUrl];
    });
}

- (void)saveToPasteBoard:(NSURL*) url
{
    UIPasteboard *appPasteBoard = [UIPasteboard pasteboardWithName:@"WPJ"
                                                            create:YES];
    appPasteBoard.persistent = YES;
    url = [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@", url.absoluteString, @"sourceApplication",[[NSBundle mainBundle] bundleIdentifier]]];
    [appPasteBoard setURL:url];
}

- (void)handleBrokerFromWebiewResponse:(NSString*)urlString
                              resource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                                userId:(NSString*)userId
                  extraQueryParameters:(NSString*)queryParams
                         correlationId:(NSUUID*)correlationId
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    ADAuthenticationError* error = nil;
    if(![ADAuthenticationContext respondsToUrl:[redirectUri absoluteString]])
    {
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_REDIRECT_URI
                                                       protocolCode:nil
                                                       errorDetails:ADRedirectUriInvalidError];
        completionBlock([ADAuthenticationResult resultFromError:error]);
        return;
    }
    
    ADBrokerKeyHelper* brokerHelper = [[ADBrokerKeyHelper alloc] initHelper];
    NSData* key = [brokerHelper getBrokerKey:&error];
    NSString* base64Key = [NSString Base64EncodeData:key];
    NSString* base64UrlKey = [base64Key adUrlFormEncode];
    
    NSDictionary* queryDictionary = @{
                                      @"authority": self.authority,
                                      @"resource" : resource,
                                      @"client_id": clientId,
                                      @"redirect_uri": redirectUri.absoluteString,
                                      @"username": userId,
                                      @"correlation_id": [correlationId UUIDString],
                                      @"broker_key": base64UrlKey,
                                      @"client_version": [ADLogger getAdalVersion],
                                      @"extra_qp": queryParams,
                                      };
    NSString* query = [queryDictionary adURLFormEncode];
    
    NSURL* appUrl = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@&%@", urlString, query]];
    [[ADBrokerNotificationManager sharedInstance] enableOnActiveNotification:completionBlock];
    
    if([[UIApplication sharedApplication] canOpenURL:appUrl])
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] openURL:appUrl];
        });
    }
    else
    {
        //no broker installed. go to app store
        NSString* qp = [appUrl query];
        NSDictionary* qpDict = [NSDictionary adURLFormDecode:qp];
        NSString* url = [qpDict valueForKey:@"app_link"];
        [self saveToPasteBoard:appUrl];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] openURL:[[NSURL alloc] initWithString:url]];
        });
    }
}

@end

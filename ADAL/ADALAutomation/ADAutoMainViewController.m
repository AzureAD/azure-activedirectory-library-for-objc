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

#import "ADAutoMainViewController.h"
#import "ADAutoInputViewController.h"
#import "ADAutoResultViewController.h"
#import "ADAL_Internal.h"
#import "UIApplication+ADExtensions.h"
#import "ADAL.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"

@interface ADAutoMainViewController ()

@end

@implementation ADAutoMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)acquireToken:(id)sender
{
    ADAutoInputViewController* inputController = [ADAutoInputViewController new];
    
    [inputController startWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
     {
         if(parameters[@"error"])
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayResultJson:parameters[@"error"]];
             }];
         }
         
         bool validateAuthority = YES;
         if(parameters[@"validate_authority"])
         {
             validateAuthority = [parameters[@"validate_authority"] boolValue];
         }
         
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:validateAuthority
                                                      error:nil];
         
         if(parameters[@"use_broker"] && ![parameters[@"use_broker"] boolValue])
         {
             context.credentialsType = AD_CREDENTIALS_EMBEDDED;
         }
         
         if(parameters[@"correlation_id"])
         {
             context.correlationId = [[NSUUID alloc] initWithUUIDString:parameters[@"correlation_id"]];
         }
         
         
         ADPromptBehavior promptBehavior = AD_PROMPT_AUTO;
         NSString* promptValue = parameters[@"prompt_behavior"];
         if(promptValue)
         {
             if ([NSString adSame:[promptValue lowercaseString] toString:@"refresh_session"])
             {
                 promptBehavior = AD_PROMPT_REFRESH_SESSION;
             }
             else if ([NSString adSame:[promptValue lowercaseString] toString:@"always"])
             {
                 promptBehavior = AD_PROMPT_ALWAYS;
             }
         }
         
         NSString* userId = parameters[@"user_identifier"];
         ADUserIdentifier* userIdentifier = nil;
         if(userId)
         {
             //default identifier type is RequiredDisplayableId
             userIdentifier = [ADUserIdentifier identifierWithId:userId];
             NSString* userIdType = parameters[@"user_identifier_type"];
             if(userIdType)
             {
                 if ([NSString adSame:[userIdType lowercaseString] toString:@"unique_id"])
                 {
                     userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                          typeFromString:@"UniqueId"];
                 }
                 else if ([NSString adSame:[userIdType lowercaseString] toString:@"optional_displayable"])
                 {
                     userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                          typeFromString:@"OptionalDisplayableId"];
                 }
             }
         }
         
         
         [context acquireTokenWithResource:parameters[@"resource"]
                                  clientId:parameters[@"client_id"]
                               redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                            promptBehavior:promptBehavior
                            userIdentifier:userIdentifier
                      extraQueryParameters:parameters[@"extra_qp"]
                           completionBlock:^(ADAuthenticationResult *result)
          {
              [self dismissViewControllerAnimated:NO completion:^{
                  
                  [self displayAuthenticationResult:result];
              }];
          }];
     }];
}


- (IBAction)acquireTokenSilent:(id)sender
{
    ADAutoInputViewController* inputController = [ADAutoInputViewController new];
    
    [inputController startWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
     {
         if(parameters[@"error"])
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayResultJson:parameters[@"error"]];
             }];
         }
         
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:[parameters[@"validate_authority"] boolValue]
                                                      error:nil];
         
         if(parameters[@"use_broker"] && ![parameters[@"use_broker"] boolValue])
         {
             context.credentialsType = AD_CREDENTIALS_EMBEDDED;
         }
         
         if(parameters[@"correlation_id"])
         {
             context.correlationId = [[NSUUID alloc] initWithUUIDString:parameters[@"correlation_id"]];
         }
         
         [context acquireTokenSilentWithResource:parameters[@"resource"]
                                        clientId:parameters[@"client_id"]
                                     redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                                          userId:parameters[@"user_identifier"]
                                 completionBlock:^(ADAuthenticationResult *result)
          {
              [self dismissViewControllerAnimated:NO completion:^{
                  
                  [self displayAuthenticationResult:result];
              }];
          }];
     }];
}

- (IBAction)readCache:(id)sender
{
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    NSArray* allItems = [cache allItems:nil];
    NSMutableDictionary* cacheDictionary = [NSMutableDictionary new];
    [cacheDictionary setValue:[NSString stringWithFormat:@"%lu", (unsigned long)allItems.count] forKey:@"item_count"];
    
    NSMutableArray * arr = [[NSMutableArray alloc] init];
    for(ADTokenCacheItem* item in allItems)
    {
        [arr addObject:[self createDictionaryFromTokenCacheItem:item]];
    }
    
    [cacheDictionary setValue:arr forKey:@"items"];
    [self displayResultJson:[self createJsonStringFromDictionary:cacheDictionary]];
}

- (IBAction)clearCache:(id)sender
{
    
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    NSArray* allItems = [cache allItems:nil];
    
    for (id object in allItems) {
        [cache removeItem:object error:nil];
    }
    
    [self displayResultJson:[NSString stringWithFormat:@"{\"cleared_items_count\":\"%lu\"}", (unsigned long)allItems.count]];
}

- (IBAction)invalidateRefreshToken:(id)sender
{
    ADAutoInputViewController* inputController = [ADAutoInputViewController new];
    
    [inputController startWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
     {
         if(parameters[@"error"])
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayResultJson:parameters[@"error"]];
             }];
         }
         
         ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
         
         ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:parameters[@"authority"]
                                                         resource:parameters[@"resource"]
                                                         clientId:parameters[@"client_id"]
                                                            error:nil];
         
         NSArray<ADTokenCacheItem *>* items = [cache getItemsWithKey:key
                                                              userId:parameters[@"user_id"]
                                                       correlationId:nil
                                                               error:nil];
         
         int refreshTokenCount = 0;
         
         for(ADTokenCacheItem* item in items)
         {
             if(item.refreshToken){
                 refreshTokenCount++;
                 item.refreshToken = @"bad-refresh-token";
                 [cache addOrUpdateItem:item correlationId:nil error:nil];
             }
         }
         
         [self dismissViewControllerAnimated:NO completion:^{
             
             [self displayResultJson:[NSString stringWithFormat:@"{\"invalidated_refresh_token_count\":\"%d\"}", refreshTokenCount]];
         }];
     }];
}

- (IBAction)expireAccessToken:(id)sender
{
    ADAutoInputViewController* inputController = [ADAutoInputViewController new];
    
    [inputController startWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
     {
         if(parameters[@"error"])
         {
             [self dismissViewControllerAnimated:NO completion:^{
                 [self displayResultJson:parameters[@"error"]];
             }];
         }
         
         ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
         ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:parameters[@"authority"]
                                                         resource:parameters[@"resource"]
                                                         clientId:parameters[@"client_id"]
                                                            error:nil];
         
         NSArray<ADTokenCacheItem *>* items = [cache getItemsWithKey:key
                                                              userId:parameters[@"user_id"]
                                                       correlationId:nil
                                                               error:nil];
         
         int accessTokenCount = 0;
         
         for(ADTokenCacheItem* item in items)
         {
             if(item.accessToken){
                 accessTokenCount++;
                 item.expiresOn = [NSDate new];
                 [cache addOrUpdateItem:item correlationId:nil error:nil];
             }
         }
         
         [self dismissViewControllerAnimated:NO completion:^{
             
             [self displayResultJson:[NSString stringWithFormat:@"{\"expired_access_token_count\":\"%d\"}", accessTokenCount]];
         }];
     }];
}

-(void) displayAuthenticationResult:(ADAuthenticationResult*) result {
    [self displayResultJson:[self createJsonFromResult:result]];
}

-(void) displayResultJson:(NSString*) resultJson {
    
    ADAutoResultViewController* resultController = [[ADAutoResultViewController alloc] initWithResultJson:resultJson];
    [[UIApplication adCurrentViewController] presentViewController:resultController animated:NO completion:^{
        NSLog(@"Result view controller loaded");
    }];
}

- (NSString*) createJsonFromResult:(ADAuthenticationResult*) result
{
    NSMutableDictionary* resultDict = [NSMutableDictionary new];
    
    if(result.error){
        [resultDict setValue:result.error.errorDetails forKey:@"error"];
        [resultDict setValue:result.error.description forKey:@"error_description"];
    }
    else {
        
        NSString * isExtLtString = (result.extendedLifeTimeToken) ? @"true" : @"false";
        [resultDict setValue:isExtLtString forKey:@"extended_lifetime_token"];
        
        [result setValuesForKeysWithDictionary:[self createDictionaryFromTokenCacheItem:result.tokenCacheItem]];
    }
    
    return [self createJsonStringFromDictionary:resultDict];
}

- (NSDictionary*) createDictionaryFromTokenCacheItem:(ADTokenCacheItem*) item
{
    NSMutableDictionary* resultDict = [NSMutableDictionary new];
    [resultDict setValue:item.accessToken forKey:@"access_token"];
    [resultDict setValue:item.refreshToken forKey:@"refresh_token"];
    [resultDict setValue:item.accessTokenType forKey:@"access_token_type"];
    [resultDict setValue:[NSString stringWithFormat:@"%ld", (long)item.expiresOn.timeIntervalSince1970] forKey:@"expires_on"];
    
    
    NSString * isMrrtString = (item.isMultiResourceRefreshToken) ? @"true" : @"false";
    [resultDict setValue:isMrrtString forKey:@"mrrt"];
    
    if(item.userInformation){
        [resultDict setValue:item.userInformation.rawIdToken
                      forKey:@"id_token"];
        [resultDict setValue:item.userInformation.identityProvider
                      forKey:@"identity_provider"];
        [resultDict setValue:item.userInformation.tenantId
                      forKey:@"tenant_id"];
        [resultDict setValue:item.userInformation.givenName
                      forKey:@"given_name"];
        [resultDict setValue:item.userInformation.guestId
                      forKey:@"guest_id"];
        [resultDict setValue:item.userInformation.familyName
                      forKey:@"family_name"];
        [resultDict setValue:item.userInformation.uniqueId
                      forKey:@"unique_id"];
        if(item.userInformation.userIdDisplayable)
        {
            [resultDict setValue:item.userInformation.userId
                          forKey:@"displayable_id"];
        }
    }
    
    return resultDict;
}


- (NSString*) createJsonStringFromDictionary:(NSDictionary*) dictionary
{
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];

    if (! jsonData) {
        return [NSString stringWithFormat:@"{\"error\" : \"%@\"}", error.description];
    }
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}


@end

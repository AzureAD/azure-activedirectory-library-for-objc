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
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:YES
                                                      error:nil];
         
         [context acquireTokenWithResource:parameters[@"resource"]
                                  clientId:parameters[@"client_id"]
                               redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
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
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:[parameters[@"validate_authority"] boolValue]
                                                      error:nil];
         
         [context acquireTokenSilentWithResource:parameters[@"resource"]
                                  clientId:parameters[@"client_id"]
                               redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
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
    [self displayResultJson:[NSString stringWithFormat:@"{\"item_count\":\"%lu\"}", (unsigned long)allItems.count]];
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
        
        [resultDict setValue:result.accessToken forKey:@"access_token"];
        if(result.tokenCacheItem.userInformation){
            [resultDict setValue:result.tokenCacheItem.userInformation.rawIdToken
                          forKey:@"id_token"];
            [resultDict setValue:result.tokenCacheItem.userInformation.upn
                          forKey:@"upn"];
        }
    }
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:resultDict
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    NSString* resultString = nil;
    
    if (! jsonData) {
        return [NSString stringWithFormat:@"{\"error\" : \"%@\"}", error.description];
    }
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

@end

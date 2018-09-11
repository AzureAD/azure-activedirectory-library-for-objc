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

#import "ADAutoMainViewController.h"
#import "ADAL_Internal.h"
#import "ADAL.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"
#import "MSIDAadAuthorityCache.h"
#import "MSIDLegacyTokenCacheKey.h"
#import <ADAL/ADTelemetry.h>
#import "MSIDAADAuthority.h"

@interface ADAutoMainViewController () <ADDispatcher>

@property (atomic) NSMutableString *resultLogs;

@end

@implementation ADAutoMainViewController

- (void)viewDidLoad
{
    [super viewDidLoad];

    [ADLogger setLoggerCallback:^(ADAL_LOG_LEVEL __unused logLevel, NSString *message, BOOL __unused containsPii)
     {
         if (self.resultLogs)
         {
             [self.resultLogs appendString:message];
         }
     }];

    [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];
    [[ADTelemetry sharedInstance] addDispatcher:self aggregationRequired:YES];
}

- (ADAuthenticationContext *)contextFromParameters:(NSDictionary *)parameters
{
    BOOL validateAuthority = YES;

    if (parameters[@"validate_authority"])
    {
        validateAuthority = parameters[@"validate_authority"] ? [parameters[@"validate_authority"] boolValue] : YES;
    }

    ADAuthenticationContext *context = [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                                                        validateAuthority:validateAuthority
                                                                                    error:nil];

    NSString *webViewType = parameters[@"web_view"];

    if (webViewType && [webViewType isEqualToString:@"passed_in"])
    {
        [self showPassedInWebViewControllerWithContext:context];
    }
    else
    {
        context.webView = nil;
    }

    if (parameters[@"use_broker"])
    {
        if ([parameters[@"use_broker"] boolValue])
        {
            context.credentialsType = AD_CREDENTIALS_AUTO;
        }
        else context.credentialsType = AD_CREDENTIALS_EMBEDDED;
    }

    if (parameters[@"correlation_id"])
    {
        context.correlationId = [[NSUUID alloc] initWithUUIDString:parameters[@"correlation_id"]];
    }

    return context;
}

- (void)dispatchEvent:(nonnull NSDictionary<NSString*, NSString*> *)event
{
    /* We don't want to do anything in the automation app with the event */
}

- (IBAction)acquireToken:(__unused id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        ADAuthenticationContext *context = [self contextFromParameters:parameters];

        ADPromptBehavior promptBehavior = AD_PROMPT_AUTO;
        NSString *promptValue = parameters[@"prompt_behavior"];
        if (promptValue)
        {
            if ([[promptValue lowercaseString] isEqualToString:@"refresh_session"])
            {
                promptBehavior = AD_PROMPT_REFRESH_SESSION;
            }
            else if ([[promptValue lowercaseString] isEqualToString:@"always"])
            {
                promptBehavior = AD_PROMPT_ALWAYS;
            }
            else if ([[promptValue lowercaseString] isEqualToString:@"force"])
            {
                promptBehavior = AD_FORCE_PROMPT;
            }
        }

        NSString *userId = parameters[@"user_identifier"];
        ADUserIdentifier *userIdentifier = nil;
        if (userId)
        {
            //default identifier type is RequiredDisplayableId
            userIdentifier = [ADUserIdentifier identifierWithId:userId];
            NSString *userIdType = parameters[@"user_identifier_type"];
            if(userIdType)
            {
                if ([[userIdType lowercaseString] isEqualToString:@"unique_id"])
                {
                    userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                         typeFromString:@"UniqueId"];
                }
                else if ([[userIdType lowercaseString] isEqualToString:@"optional_displayable"])
                {
                    userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                         typeFromString:@"OptionalDisplayableId"];
                }
                else if ([[userIdType lowercaseString] isEqualToString:@"required_displayable"])
                {
                    userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                         typeFromString:@"RequiredDisplayableId"];
                }
            }
        }

        NSURL *redirectUri = [NSURL URLWithString:parameters[@"redirect_uri"]];

        if ([parameters[@"use_broker"] boolValue])
        {
            redirectUri = [NSURL URLWithString:@"x-msauth-adaltestapp-210://com.microsoft.adal.2.1.0.TestApp"];
        }

        [context acquireTokenWithResource:parameters[@"resource"]
                                 clientId:parameters[@"client_id"]
                              redirectUri:redirectUri
                           promptBehavior:promptBehavior
                           userIdentifier:userIdentifier
                     extraQueryParameters:parameters[@"extra_qp"]
                                   claims:parameters[@"claims"]
                          completionBlock:^(ADAuthenticationResult *result)
         {
             dispatch_async(dispatch_get_main_queue(), ^{
                 [weakSelf displayAuthenticationResult:result logs:weakSelf.resultLogs];
             });
         }];

    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)acquireTokenSilent:(__unused id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        ADAuthenticationContext *context = [self contextFromParameters:parameters];

        [context acquireTokenSilentWithResource:parameters[@"resource"]
                                       clientId:parameters[@"client_id"]
                                    redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                                         userId:parameters[@"user_identifier"]
                                completionBlock:^(ADAuthenticationResult *result) {

                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        [weakSelf displayAuthenticationResult:result logs:weakSelf.resultLogs];
                                    });
        }];

    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)readCache:(__unused id)sender
{
    id<ADTokenCacheDataSource> dataSource = [self cacheDatasource];
    NSArray *allItems = [dataSource allItems:nil];
    NSMutableDictionary *cacheDictionary = [NSMutableDictionary new];
    [cacheDictionary setValue:[NSString stringWithFormat:@"%lu", (unsigned long)allItems.count] forKey:@"item_count"];

    NSMutableArray *arr = [[NSMutableArray alloc] init];
    for (ADTokenCacheItem *item in allItems)
    {
        [arr addObject:[self createDictionaryFromTokenCacheItem:item]];
    }

    [cacheDictionary setValue:arr forKey:@"items"];
    [self showResultViewWithResult:[self createJsonStringFromDictionary:cacheDictionary] logs:_resultLogs];
}

- (IBAction)clearCache:(__unused id)sender
{
    id<ADTokenCacheDataSource> dataSource = [self cacheDatasource];
    NSUInteger allItemsCount = [[dataSource allItems:nil] count];
    [self clearCache];
    [self showResultViewWithResult:[NSString stringWithFormat:@"{\"cleared_items_count\":\"%lu\"}", (unsigned long)allItemsCount] logs:_resultLogs];
}

- (IBAction)clearCookies:(id)sender
{
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    int count = 0;
    for (NSHTTPCookie *cookie in cookieStore.cookies)
    {
        [cookieStore deleteCookie:cookie];
        count++;
    }

    // Clear WKWebView cookies

    NSSet *allTypes = [WKWebsiteDataStore allWebsiteDataTypes];
    [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:allTypes
                                               modifiedSince:[NSDate dateWithTimeIntervalSince1970:0]
                                           completionHandler:^{
                                               NSLog(@"Completed!");
                                           }];

    [self showResultViewWithResult:[NSString stringWithFormat:@"{\"cleared_items_count\":\"%lu\"}", (unsigned long)count] logs:_resultLogs];
}

- (IBAction)clearKeychain:(id)sender
{
    [self clearKeychain];
    [self showResultViewWithResult:@"{\"cleared keychain with status\":\"1\"}" logs:_resultLogs];
}

- (IBAction)invalidateRefreshToken:(__unused id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        id<ADTokenCacheDataSource> cache = [self cacheDatasource];

        NSMutableArray<ADTokenCacheItem *> *allItems = [NSMutableArray new];
        
        __auto_type aadAuthority = [[MSIDAADAuthority alloc] initWithURL:[NSURL URLWithString:parameters[@"authority"]]  context:nil error:nil];

        NSArray *aliases = [[MSIDAadAuthorityCache sharedInstance] cacheAliasesForAuthority:aadAuthority];

        for (NSURL *alias in aliases)
        {
            ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:alias.absoluteString
                                                            resource:parameters[@"resource"]
                                                            clientId:parameters[@"client_id"]
                                                               error:nil];

            NSArray<ADTokenCacheItem *> *items = [cache getItemsWithKey:key
                                                                 userId:parameters[@"user_identifier"]
                                                          correlationId:nil
                                                                  error:nil];

            [allItems addObjectsFromArray:items];
        }

        int refreshTokenCount = 0;

        for (ADTokenCacheItem *item in allItems)
        {
            if (item.refreshToken)
            {
                refreshTokenCount++;
                item.refreshToken = @"bad-refresh-token";
                [cache addOrUpdateItem:item correlationId:nil error:nil];
            }
        }

        NSString *resultJson = [NSString stringWithFormat:@"{\"invalidated_refresh_token_count\":\"%d\"}", refreshTokenCount];
        [weakSelf showResultViewWithResult:resultJson logs:weakSelf.resultLogs];
    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)openURLInSafari:(__unused id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        NSString *resultJson = @"{\"success\":\"1\"}";
        [weakSelf showResultViewWithResult:resultJson logs:@""];
        
        [self openURL:[NSURL URLWithString:parameters[@"safari_url"]]];
    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)expireAccessToken:(__unused id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        id<ADTokenCacheDataSource> cache = [self cacheDatasource];

        NSMutableArray<ADTokenCacheItem *> *allItems = [NSMutableArray new];
        
        __auto_type aadAuthority = [[MSIDAADAuthority alloc] initWithURL:[NSURL URLWithString:parameters[@"authority"]]  context:nil error:nil];

        NSArray *aliases = [[MSIDAadAuthorityCache sharedInstance] cacheAliasesForAuthority:aadAuthority];

        for (NSURL *alias in aliases)
        {
            ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:alias.absoluteString
                                                            resource:parameters[@"resource"]
                                                            clientId:parameters[@"client_id"]
                                                               error:nil];

            [allItems addObjectsFromArray:[cache getItemsWithKey:key
                                                          userId:parameters[@"user_identifier"]
                                                   correlationId:nil
                                                           error:nil]];
        }

        int accessTokenCount = 0;

        for (ADTokenCacheItem *item in allItems)
        {
            if (item.accessToken)
            {
                accessTokenCount++;
                item.expiresOn = [NSDate new];
                [cache addOrUpdateItem:item correlationId:nil error:nil];
            }
        }

        NSString *resultJson = [NSString stringWithFormat:@"{\"expired_access_token_count\":\"%d\"}", accessTokenCount];
        [weakSelf showResultViewWithResult:resultJson logs:weakSelf.resultLogs];
    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)deleteSpecificTokens:(id)sender
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        NSString *userIdentifier = parameters[@"user_identifier"];
        NSString *clientId = parameters[@"client_id"];

        id<ADTokenCacheDataSource> cache = [self cacheDatasource];

        NSError *error = nil;

        if (userIdentifier && clientId)
        {
            [cache removeAllForUserId:userIdentifier clientId:clientId error:&error];
        }
        else if (clientId)
        {
            [cache removeAllForClientId:clientId error:&error];
        }
        else if (userIdentifier)
        {
            [cache wipeAllItemsForUserId:userIdentifier error:&error];
        }

        NSString *resultJson = [NSString stringWithFormat:@"{\"delete_result\":\"%d\", \"error\":\"%@\"}", error != nil, error];

        [weakSelf showResultViewWithResult:resultJson logs:weakSelf.resultLogs];

    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)acquireTokenByRefreshToken:(id)sender
{

    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        weakSelf.resultLogs = [NSMutableString new];

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                      logs:weakSelf.resultLogs];

            return;
        }

        NSString *refreshToken = parameters[@"refresh_token"];

        ADAuthenticationContext* context =
        [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                         validateAuthority:NO
                                                     error:nil];

        [context acquireTokenWithRefreshToken:refreshToken
                                     resource:parameters[@"resource"]
                                     clientId:parameters[@"client_id"]
                                  redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                              completionBlock:^(ADAuthenticationResult *result) {
                                  dispatch_async(dispatch_get_main_queue(), ^{
                                      [weakSelf displayAuthenticationResult:result logs:weakSelf.resultLogs];
                                  });
                              }];

    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (IBAction)interactivePollingStressTest:(id)sender
{
    [self runStressTestWithStop:YES removeToken:NO];
}

- (IBAction)emptyCacheStressTest:(id)sender
{
    [self runStressTestWithStop:NO removeToken:NO];
}

- (IBAction)nonEmptyCacheStressTest:(id)sender
{
    [self runStressTestWithStop:NO removeToken:YES];
}

- (void)runStressTestWithStop:(BOOL)stopOnSuccess removeToken:(BOOL)removeToken
{
    __weak typeof(self) weakSelf = self;

    void (^completionBlock)(NSDictionary<NSString *, NSString *> * parameters) = ^void(NSDictionary<NSString *, NSString *> * parameters) {

        /*
         For stress tests we don't want to accumulate all the logs, otherwise it will run out of memory.
         */
        weakSelf.resultLogs = nil;

        if (parameters[@"error"])
        {
            [weakSelf showResultViewWithResult:parameters[@"error"]
                                          logs:weakSelf.resultLogs];

            return;
        }

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

            dispatch_semaphore_t sem = dispatch_semaphore_create(10);

            __block BOOL stop = NO;

            while (stopOnSuccess ? !stop : YES)
            {
                dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

                    ADAuthenticationError *error = nil;
                    ADAuthenticationContext *context = [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                                                                        validateAuthority:YES
                                                                                                    error:&error];

                    [context acquireTokenSilentWithResource:parameters[@"resource"]
                                                   clientId:parameters[@"client_id"]
                                                redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                                                     userId:parameters[@"user_identifier"]
                                            completionBlock:^(ADAuthenticationResult *result) {

                                                if (result.status == AD_SUCCEEDED)
                                                {
                                                    if (stopOnSuccess)
                                                    {
                                                        stop = YES;
                                                    }
                                                    else if (removeToken)
                                                    {
                                                        id<ADTokenCacheDataSource> cache = [weakSelf cacheDatasource];
                                                        [cache removeItem:result.tokenCacheItem error:nil];
                                                    }
                                                }

                                                dispatch_semaphore_signal(sem);
                                            }];
                });
            }

            if (stopOnSuccess)
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [weakSelf showResultViewWithResult:@"{\"result\": \"1\"}" logs:weakSelf.resultLogs];
                });
            }
        });

        if (stopOnSuccess)
        {
            ADAuthenticationContext *context = [self contextFromParameters:parameters];

            [context acquireTokenWithResource:parameters[@"resource"]
                                     clientId:parameters[@"client_id"]
                                  redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                                       userId:parameters[@"user_identifier"]
                              completionBlock:^(ADAuthenticationResult *result) {
                                  (void) result;
                              }];
        }
    };

    [self showRequestDataViewWithCompletionHandler:completionBlock];
}

- (void)displayAuthenticationResult:(ADAuthenticationResult *)result logs:(NSString *)resultLogs
{
    [self showResultViewWithResult:[self createJsonFromResult:result] logs:resultLogs];
}

- (NSString *)createJsonFromResult:(ADAuthenticationResult *)result
{
    NSMutableDictionary *resultDict = [NSMutableDictionary new];

    if(result.error){
        [resultDict setValue:result.error.errorDetails forKey:@"error"];
        [resultDict setValue:result.error.description forKey:@"error_description"];
        [resultDict setValue:[ADAuthenticationError stringForADErrorCode:result.error.code] forKey:@"error_code"];
    }
    else {
        NSString * isExtLtString = (result.extendedLifeTimeToken) ? @"true" : @"false";
        [resultDict setValue:isExtLtString forKey:@"extended_lifetime_token"];
        [resultDict addEntriesFromDictionary:[self createDictionaryFromTokenCacheItem:result.tokenCacheItem]];
    }

    return [self createJsonStringFromDictionary:resultDict];
}

- (NSDictionary *)createDictionaryFromTokenCacheItem:(ADTokenCacheItem *)item
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


- (NSString *)createJsonStringFromDictionary:(NSDictionary *)dictionary
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

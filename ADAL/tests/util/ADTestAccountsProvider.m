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

#import "ADTestAccountsProvider.h"

#define StringName(arg) (@""#arg)

// Header file at ~/aadoverrides/ADTestAccounts.h
#if __has_include("ADTestAccounts.h")
#include "ADTestAccounts.h"
#else
static NSDictionary* _testAccounts()
{
    return nil;
}

static NSDictionary* _testProfiles()
{
    return nil;
}

static NSString *kPwdAPIUrl = @"not a valid URL";
static NSString *kPwdAuthCookie = @"not a valid cookie";

static NSString *kAPIScheme = @"https";
static NSString *kAPIHost = @"api url";
static NSString *kAPIPath = @"api path";
#endif

@interface ADTestAccountsProvider()

@property (nonatomic, strong) NSMutableDictionary *cachedConfigurations;

@end

@implementation ADTestAccountsProvider

/*! WW is a world wide entirely on-cloud account */
ADTestAccountProvider ADTestAccountProviderWW = @"ww";
/*! Black Forest is an AAD account hosted in the Black Forest sovereign cloud (.de) */
ADTestAccountProvider ADTestAccountProviderBlackForest = @"bf";
/*! A WW account federated using ADFSv2 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv2 = @"adfsv2";
/*! A WW account federated using ADFSv3 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv3 = @"adfsv3";
/*! A WW account federated using ADFSv4 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv4 = @"adfsv4";
/*! A WW account federated using Shibboleth */
ADTestAccountProvider ADTestAccountProviderShibboleth = @"shib";
/*! A WW account federated using Ping */
ADTestAccountProvider ADTestAccountProviderPing = @"ping";

ADTestAccountFeature ADTestAccountFeatureMDMEnabled = @"mam";
ADTestAccountFeature ADTestAccountFeatureMAMEnabled = @"mdm";
ADTestAccountFeature ADTestAccountFeatureDeviceAuth = @"device";
ADTestAccountFeature ADTestAccountFeatureMFAEnabled = @"mfa";

ADTestApplication ADTestApplicationCloud = @"cloud";
ADTestApplication ADTestApplicationOnPremAdfsv2 = @"adfsv2";
ADTestApplication ADTestApplicationOnPremAdfsv3 = @"adfsv3";
ADTestApplication ADTestApplicationOnPremAdfsv4 = @"adfsv4";
ADTestApplication ADTestApplicationRequiresDeviceAuth = @"device";
ADTestApplication ADTestApplicationRequiresMFA = @"mfa";
ADTestApplication ADTestApplicationRequiresMDM = @"mdm";
ADTestApplication ADTestApplicationRequiresMAM = @"mam";

- (instancetype)init
{
    self = [super init];

    if (self)
    {
        _cachedConfigurations = [NSMutableDictionary dictionary];
    }

    return self;
}

- (void)configurationWithRequest:(ADTestConfigurationRequest *)request
               completionHandler:(void (^)(ADTestConfiguration *configuration))completionHandler
{
    if (_cachedConfigurations[request])
    {
        if (completionHandler)
        {
            completionHandler(_cachedConfigurations[request]);
        }

        return;
    }

    NSURL *resultURL = [request requestURLWithAPIScheme:kAPIScheme host:kAPIHost path:kAPIPath];

    [[[NSURLSession sharedSession] dataTaskWithURL:resultURL
                                 completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error)
      {
          if (error)
          {
              if (completionHandler)
              {
                  completionHandler(nil);
              }

              return;
          }

          ADTestConfiguration *configuration = [[ADTestConfiguration alloc] initWithJSONResponseData:data];
          _cachedConfigurations[request] = configuration;

          if (completionHandler)
          {
              completionHandler(configuration);
          }

      }] resume];
}

- (void)passwordForAccount:(ADTestAccount *)account
         completionHandler:(void (^)(NSString *password))completionHandler
{
    if (account.password)
    {
        completionHandler(account.password);
    }

    NSString *urlString = [NSString stringWithFormat:kPwdAPIUrl, account.labName];
    NSURL *url = [NSURL URLWithString:urlString];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setValue:kPwdAuthCookie forHTTPHeaderField:@"Cookie"];

    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {

        if (error)
        {
            if (completionHandler)
            {
                completionHandler(nil);
            }

            return;
        }

        NSString *password = [account passwordFromData:data];

        if (password)
        {
            account.password = password;
        }

        if (completionHandler)
        {
            completionHandler(password);
        }

    }] resume];
}

+ (NSArray *)accounts {
    static NSArray *accounts = nil;
    static dispatch_once_t once;
    
    dispatch_once(&once, ^{
        accounts = @[ @{ @"upn" : @"aduser1@msidlab13.com",
                         @"username" : @"aduser1",
                         @"provider" : ADTestAccountProviderShibboleth,
                         @"secret_id" : @"msidlab13", },
                      @{ @"upn" : @"fIDLAB@msidlab9.com",
                         @"username" : @"fIDLAB",
                         @"provider" : ADTestAccountProviderPing,
                         @"secret_id" : @"msidlab9" },
                      @{ @"upn" : @"IDLAB@msidlab12.onmicrosoft.com",
                         @"secret_id" : @"msidlab12",
                         @"provider" : ADTestAccountProviderWW },
                      @{ @"upn" : @"fIDLAB@msidlab7.com",
                         @"secret_id" : @"msidlab7",
                         @"provider" : ADTestAccountProviderAdfsv2 },
                      @{ @"upn" : @"fIDLAB@msidlab5.com",
                         @"secret_id" : @"msidlab5",
                         @"provider" : ADTestAccountProviderAdfsv3 },
                      @{ @"upn" : @"fIDLAB@msidlab12.com",
                         @"secret_id" : @"msidlab12",
                         @"provider" : ADTestAccountProviderAdfsv4 },
                      @{ @"upn" : @"IDLABMAMCA@msidlab4.onmicrosoft.com",
                         @"secret_id" : @"msidlab4",
                         @"provider" : ADTestAccountProviderWW,
                         @"features" : [NSSet setWithArray:@[ ADTestAccountFeatureMAMEnabled, ADTestAccountFeatureDeviceAuth ]] }
                      ];
    });
    
    return accounts;
}

- (void)getMetadataForProvider:(ADTestAccountProvider)provider
                  withFeatures:(NSSet<ADTestAccountFeature> *)features
               completionBlock:(void (^)(NSDictionary *))completionBlock
{
    // This is async because it'll eventually need to be when we get the data from the API server instead
    // of hardcoded
    
    NSArray *accounts = [[self class] accounts];
    for (NSDictionary *account in accounts)
    {
        if ([provider isEqualToString:account[@"provider"]])
        {
            NSSet *accountFeatures = account[@"features"];
            if (accountFeatures == nil)
            {
                if (features == nil)
                {
                    completionBlock(account);
                    return;
                }
                
                continue;
            }
            
            if ([accountFeatures isEqualToSet:features])
            {
                completionBlock(account);
                return;
            }
        }
    }
    
    completionBlock(nil);
    return;
}

- (void)getAccountForProvider:(ADTestAccountProvider)provider
                 withFeatures:(NSArray<ADTestAccountFeature> *)features
              completionBlock:(void (^)(ADTestAccount *))completionBlock
{
    NSSet<ADTestAccountFeature> *featureSet = features ? [NSSet setWithArray:features] : nil;
    [self getMetadataForProvider:provider withFeatures:featureSet completionBlock:^(NSDictionary *account) {
        if (!account)
        {
            completionBlock(nil);
            return;
        }
        
        NSString *secretId = account[@"secret_id"];
        NSAssert(secretId, @"secret id must be defined");
        NSString *secretUrlString = [NSString stringWithFormat:@"https://msidlabs.vault.azure.net/secrets/%@", secretId];
        NSAssert(secretUrlString, @"secret id must form good string");
        NSURL *secretUrl = [NSURL URLWithString:secretUrlString];
        NSAssert(secretUrl, @"secret url must be valid");
        
        ADTestAccount *testAccount = [ADTestAccount new];
        testAccount.account = account[@"upn"];
        const char *envSecret = getenv(secretId.UTF8String);
        if (envSecret)
        {
            testAccount.password = [NSString stringWithUTF8String:envSecret];
        }
        testAccount.username = account[@"username"];
        
        completionBlock(testAccount);
    }];
}

// Synchronous helper version of above, note this call *will* block until it receives a network
// response
- (ADTestAccount *)getAccountForProvider:(ADTestAccountProvider)provider
                            withFeatures:(NSArray<ADTestAccountFeature> *)features
{
    __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block ADTestAccount *account = nil;
    
    [self getAccountForProvider:provider withFeatures:features completionBlock:^(ADTestAccount *outAccount) {
        account = outAccount;
        
        dispatch_semaphore_signal(sem);
    }];
    
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    
    return account;
}


- (NSString *)accountTypeToString:(ADTestAccountType)type
{
    NSDictionary *map = @{
                          @(ADTestAccountTypeAAD) : StringName(ADTestAccountTypeAAD),
                          @(ADTestAccountTypePing) : StringName(ADTestAccountTypePing),
                          @(ADTestAccountTypeADFSv3) : StringName(ADTestAccountTypeADFSv3),
                          @(ADTestAccountTypeBlackforest) : StringName(ADTestAccountTypeBlackforest),
                          @(ADTestAccountTypeShib) : StringName(ADTestAccountTypeShib),
                          @(ADTestAccountTypeAADMDM) : StringName(ADTestAccountTypeAADMDM),
                          };
    
    return map[@(type)];
}

- (NSString *)profileTypeToString:(ADTestProfileType)type
{
    NSDictionary *map = @{
                          @(ADTestProfileTypeBasic) : @"Basic",
                          @(ADTestProfileTypeFoci) : @"Foci",
                          @(ADTestProfileTypeSovereign) : @"Sovereign",
                          @(ADTestProfileTypeBasicMDM) : @"BasicMDM",
                          };
    
    return map[@(type)];
}

- (ADTestAccount *)testAccountOfType:(ADTestAccountType)type;
{
    return [[self testAccountsOfType:type] firstObject];
}

- (NSArray <ADTestAccount *> *)testAccountsOfType:(ADTestAccountType)type
{
    NSString *stringType = [self accountTypeToString:type];
    
    NSArray *accountsInfo = _testAccounts()[stringType];
    
    NSMutableArray *availableAccounts = [NSMutableArray new];
    
    for (NSDictionary *accountInfo in accountsInfo)
    {
        ADTestAccount *account = [ADTestAccount new];
        account.account = accountInfo[@"account"];
        account.username = accountInfo[@"username"];
        account.password = accountInfo[@"password"];
        
        [availableAccounts addObject:account];
    }
    
    return availableAccounts;
}

- (NSDictionary *)testProfileOfType:(ADTestProfileType)type
{
    NSString *stringType = [self profileTypeToString:type];
    
    return _testProfiles()[stringType];
}

#pragma mark - Get configuration

@end

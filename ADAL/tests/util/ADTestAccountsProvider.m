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

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
#import <KeyVault/KeyVault.h>
#import <KeyVaultClient/KeyVaultClient.h>

#define StringName(arg) (@""#arg)

// Header file at ~/aadoverrides/ADTestAccounts.h
#if __has_include("ADTestAccounts.h")
#include "ADTestAccounts.h"
#else

static NSString *kAPIPath = @"https://api.com";

static ADTestAccount *defaultAccount()
{
    return nil;
}

static ADTestAccount *defaultLabAccount()
{
    return nil;
}

#endif

@interface ADTestAccountsProvider()

@property (nonatomic, strong) NSMutableDictionary *cachedConfigurations;
@property (nonatomic, strong) KeyVaultClient *keyvaultClient;

@end

@implementation ADTestAccountsProvider

- (instancetype)init
{
    self = [super init];

    if (self)
    {
        _cachedConfigurations = [NSMutableDictionary dictionary];
        _keyvaultClient = [[KeyVaultClient alloc] init];
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

    NSURL *resultURL = [request requestURLWithAPIPath:kAPIPath];

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
        return;
    }

    NSURL *url = [NSURL URLWithString:account.keyvaultName];

    [self.keyvaultClient getSecret:url completionBlock:^(NSString *secret, NSError *error) {

        if (error)
        {
            if (completionHandler)
            {
                completionHandler(nil);
            }

            return;
        }

        if (secret)
        {
            account.password = secret;
        }

        if (completionHandler)
        {
            completionHandler(secret);
        }

    }];
}

- (ADTestAccount *)defaultAccount
{
    return defaultAccount();
}

- (ADTestAccount *)defaultLabAccount
{
    return defaultLabAccount();
}

@end

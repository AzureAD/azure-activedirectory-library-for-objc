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

#import "ADTestConfiguration.h"

@implementation ADTestAccount

- (BOOL)isEqualToTestAccount:(ADTestAccount *)accountInfo
{
    if (!accountInfo)
    {
        return NO;
    }

    BOOL result = YES;
    result &= (!self.account && !accountInfo.account) || [self.account isEqualToString:accountInfo.account];
    result &= (!self.username && !accountInfo.username) || [self.username isEqualToString:accountInfo.username];
    result &= (!self.keyvaultName && !accountInfo.keyvaultName) || [self.keyvaultName isEqualToString:accountInfo.keyvaultName];

    return result;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)object
{
    if (self == object)
    {
        return YES;
    }

    if (![object isKindOfClass:ADTestAccount.class])
    {
        return NO;
    }

    return [self isEqualToTestAccount:(ADTestAccount *)object];
}

- (NSUInteger)hash
{
    NSUInteger hash = self.account.hash;
    hash ^= self.username.hash;
    hash ^= self.keyvaultName.hash;

    return hash;
}

- (instancetype)initWithJSONResponse:(NSDictionary *)response
{
    self = [super init];

    if (self)
    {
        NSString *homeUPN = response[@"homeUPN"];

        if (homeUPN && [homeUPN isKindOfClass:[NSString class]])
        {
            _username = homeUPN;
        }
        else
        {
            _username = response[@"upn"];
        }

        _keyvaultName = response[@"credentialVaultKeyName"];
        _labName = [_keyvaultName lastPathComponent];

        _account = _username;

        NSString *federationProvider = response[@"federationProvider"];

        // TODO: server should return a username instead
        if (federationProvider && ([federationProvider isEqualToString:@"Shibboleth"] || [federationProvider containsString:@"PingFederate"]))
        {
            NSRange range = [_username rangeOfString:@"@"];

            if (range.location != NSNotFound)
            {
                _username = [_username substringToIndex:range.location];
            }
        }

        _homeTenantId = response[@"hometenantId"];
        _targetTenantId = response[@"tenantId"];
    }

    return self;
}

- (NSString *)passwordFromData:(NSData *)responseData
{
    NSDictionary *responseDict = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:nil];

    if (!responseDict)
    {
        return nil;
    }

    return responseDict[@"Value"];
}

@end

@implementation ADTestConfiguration

- (BOOL)isEqualToConfiguration:(ADTestConfiguration *)configuration
{
    if (!configuration)
    {
        return NO;
    }

    BOOL result = YES;
    result &= (!self.authority && !configuration.authority) || [self.authority isEqualToString:configuration.authority];
    result &= (!self.clientId && !configuration.clientId) || [self.clientId isEqualToString:configuration.clientId];
    result &= (!self.redirectUri && !configuration.redirectUri) || [self.redirectUri isEqualToString:configuration.redirectUri];
    result &= (!self.resource && !configuration.resource) || [self.resource isEqualToString:configuration.resource];
    result &= (!self.accounts && !configuration.accounts) || [self.accounts isEqualToArray:configuration.accounts];

    return result;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)object
{
    if (self == object)
    {
        return YES;
    }

    if (![object isKindOfClass:ADTestConfiguration.class])
    {
        return NO;
    }

    return [self isEqualToConfiguration:(ADTestConfiguration *)object];
}

- (NSUInteger)hash
{
    NSUInteger hash = self.authority.hash;
    hash ^= self.clientId.hash;
    hash ^= self.redirectUri.hash;
    hash ^= self.resource.hash;
    hash ^= self.accounts.hash;

    return hash;
}

- (instancetype)initWithJSONResponseData:(NSData *)response
{
    self = [super init];

    if (self)
    {
        id responseObj = [NSJSONSerialization JSONObjectWithData:response options:0 error:nil];

        if (!responseObj)
        {
            return nil;
        }

        NSDictionary *responseDict = nil;

        // TODO: fix this hack on server side
        if ([responseObj isKindOfClass:[NSArray class]])
        {
            NSArray *responseArray = (NSArray *) responseObj;
            responseDict = responseArray[0];
        }
        else if ([responseObj isKindOfClass:[NSDictionary class]])
        {
            responseDict = responseObj;
        }

        _clientId = responseDict[@"AppID"];
        _redirectUri = [self redirectURIFromArray:responseDict[@"RedirectURI"]];

        // TODO: why are there multiple resources?
        _resource = responseDict[@"Resource_ids"][0];

        // TODO: fix this hack on server side
        _authority = [responseDict[@"Authority"][0] stringByAppendingString:@"common"];

        NSMutableArray *accounts = [NSMutableArray array];

        if ([responseDict[@"Users"] isKindOfClass:[NSDictionary class]])
        {
            ADTestAccount *account = [[ADTestAccount alloc] initWithJSONResponse:responseDict[@"Users"]];

            if (account)
            {
                [accounts addObject:account];
            }
        }
        else if ([responseDict[@"Users"] isKindOfClass:[NSArray class]])
        {
            for (NSDictionary *accountDict in responseDict[@"Users"])
            {
                ADTestAccount *account = [[ADTestAccount alloc] initWithJSONResponse:accountDict];

                if (account)
                {
                    [accounts addObject:account];
                }
            }
        }

        _accounts = accounts;
    }

    return self;
}

- (NSString *)redirectURIFromArray:(NSArray *)redirectUris
{
    for (NSString *uri in redirectUris)
    {
        if ([uri hasPrefix:@"x-msauth"])
        {
            return uri;
        }
    }

    return nil;
}

- (NSDictionary *)configParameters
{
    return @{@"authority" : _authority,
             @"client_id" : _clientId,
             @"redirect_uri" : _redirectUri,
             @"resource" : _resource};
}

- (NSDictionary *)configParametersWithAdditionalParams:(NSDictionary *)additionalParams
{
    NSMutableDictionary *configParams = [[self configParameters] mutableCopy];
    [configParams addEntriesFromDictionary:additionalParams];
    return configParams;
}

- (NSDictionary *)configParametersWithAdditionalParams:(NSDictionary *)additionalParams
                                               account:(ADTestAccount *)account
{
    NSMutableDictionary *configParams = [[self configParametersWithAdditionalParams:additionalParams] mutableCopy];
    return configParams;
}

- (void)addAdditionalAccount:(ADTestAccount *)additionalAccount
{
    NSMutableArray *accounts = [self.accounts mutableCopy];
    [accounts addObject:additionalAccount];
    self.accounts = accounts;
}

@end

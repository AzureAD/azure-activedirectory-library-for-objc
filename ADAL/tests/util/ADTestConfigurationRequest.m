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

#import "ADTestConfigurationRequest.h"

/*! WW is a world wide entirely on-cloud account */
ADTestAccountProvider ADTestAccountProviderWW = @"AzureCloud";
/*! Black Forest is an AAD account hosted in the Black Forest sovereign cloud (.de) */
ADTestAccountProvider ADTestAccountProviderBlackForest = @"AzureGermanyCloud";
/*! A WW account federated using ADFSv2 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv2 = @"ADFSv2";
/*! A WW account federated using ADFSv3 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv3 = @"ADFSv3";
/*! A WW account federated using ADFSv4 (these accounts can also be used for on-prem tests) */
ADTestAccountProvider ADTestAccountProviderAdfsv4 = @"ADFSv4";
/*! A WW account federated using Shibboleth */
ADTestAccountProvider ADTestAccountProviderShibboleth = @"Shibboleth";
/*! A WW account federated using Ping */
ADTestAccountProvider ADTestAccountProviderPing = @"Ping";

ADTestAccountFeature ADTestAccountFeatureMDMEnabled = @"mam";
ADTestAccountFeature ADTestAccountFeatureMAMEnabled = @"mdm";
ADTestAccountFeature ADTestAccountFeatureDeviceAuth = @"device";
ADTestAccountFeature ADTestAccountFeatureMFAEnabled = @"mfa";
ADTestAccountFeature ADTestAccountFeatureGuestUser = @"Guest";

ADTestApplication ADTestApplicationCloud = @"cloud";
ADTestApplication ADTestApplicationOnPremAdfsv2 = @"adfsv2";
ADTestApplication ADTestApplicationOnPremAdfsv3 = @"adfsv3";
ADTestApplication ADTestApplicationOnPremAdfsv4 = @"adfsv4";
ADTestApplication ADTestApplicationRequiresDeviceAuth = @"device";
ADTestApplication ADTestApplicationRequiresMFA = @"mfa";
ADTestApplication ADTestApplicationRequiresMDM = @"mdm";
ADTestApplication ADTestApplicationRequiresMAM = @"mam";

AppVersion ADAppVersionV1 = @"V1";
AppVersion ADAppVersionV2 = @"V2";

@implementation ADTestConfigurationRequest

- (BOOL)federated
{
    if ([self.accountProvider isEqualToString:ADTestAccountProviderWW]
        || [self.accountProvider isEqualToString:ADTestAccountProviderBlackForest])
    {
        return NO;
    }

    return YES;
}

- (NSString *)federatedValue
{
    if (self.federated)
    {
        return @"True";
    }

    return @"False";
}

- (NSString *)caValue
{
    if ([self.accountFeatures containsObject:ADTestAccountFeatureMAMEnabled])
    {
        return @"mamca";
    }
    else if ([self.accountFeatures containsObject:ADTestAccountFeatureMDMEnabled])
    {
        return @"mdmca";
    }
    else if([self.accountFeatures containsObject:ADTestAccountFeatureMFAEnabled])
    {
        return @"mfa";
    }

    return nil;
}

- (NSString *)userTypeValue
{
    if ([self.accountFeatures containsObject:ADTestAccountFeatureGuestUser])
    {
        return @"Guest";
    }

    return @"Member";
}

- (BOOL)isEqualToRequest:(ADTestConfigurationRequest *)request
{
    if (!request)
    {
        return NO;
    }

    BOOL result = YES;
    result &= (!self.testApplication && !request.testApplication) || [self.testApplication isEqualToString:request.testApplication];
    result &= (!self.accountProvider && !request.accountProvider) || [self.accountProvider isEqualToString:request.accountProvider];
    result &= (!self.accountFeatures && !request.accountFeatures) || [self.accountFeatures isEqualToArray:request.accountFeatures];
    result &= self.needsMultipleUsers == request.needsMultipleUsers;

    return result;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)object
{
    if (self == object)
    {
        return YES;
    }

    if (![object isKindOfClass:ADTestConfigurationRequest.class])
    {
        return NO;
    }

    return [self isEqualToRequest:(ADTestConfigurationRequest *)object];
}

- (NSUInteger)hash
{
    NSUInteger hash = self.needsMultipleUsers;
    hash ^= self.testApplication.hash;
    hash ^= self.accountProvider.hash;
    hash ^= self.accountFeatures.hash;

    return hash;
}

- (NSURL *)requestURLWithAPIPath:(NSString *)apiPath
{
    NSURLComponents *components = [[NSURLComponents alloc] initWithString:apiPath];;

    NSMutableArray *queryItems = [NSMutableArray array];
    
    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"isFederated" value:self.federatedValue]];

    NSString *caValue = self.caValue;

    if (caValue)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:caValue value:@"True"]];
    }
    else
    {
        //[queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"mdmca" value:@"False"]];
        // TODO: uncomment me, when server adds accounts
        //[queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"mamca" value:@"False"]];
    }

    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"usertype" value:self.userTypeValue]];

    if (self.federated)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"federationProvider" value:self.accountProvider]];
    }
    else
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"AzureEnvironment" value:self.accountProvider]];
    }

    if (self.needsMultipleUsers)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"DisplayAll" value:@"True"]];
    }

    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"AppVersion" value:self.appVersion]];

    components.queryItems = queryItems;
    NSURL *resultURL = [components URL];
    return resultURL;
}

- (nonnull id)copyWithZone:(nullable NSZone *)zone
{
    ADTestConfigurationRequest *request = [[ADTestConfigurationRequest allocWithZone:zone] init];
    request->_testApplication = _testApplication;
    request->_accountFeatures = _accountFeatures;
    request->_accountProvider = _accountProvider;
    request->_needsMultipleUsers = _needsMultipleUsers;
    return request;
}

@end

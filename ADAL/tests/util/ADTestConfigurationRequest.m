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

@implementation ADTestConfigurationRequest

- (NSString *)federatedValue:(ADTestUserType)userType
{
    switch (userType) {
        case ADUserTypeFederated:
            return @"True";

        default:
            return @"False";
    }
}

- (NSString *)caValue:(ADTestUserType)userType
{
    switch (userType) {
        case ADUserTypeMAM:
            return @"mamca";

        case ADUserTypeMDM:
            return @"mdmca";

        default:
            return nil;
    }
}

- (NSString *)userTypeValue:(ADTestUserType)userType
{
    switch (userType) {
        case ADUserTypeGuest:
            return @"Guest";

        default:
            return @"Member";
    }
}

- (NSString *)federationProviderValue:(ADFederationProviderType)type
{
    switch (type) {
        case ADFederationProviderShib:
            return @"Shibboleth";

        case ADFederationProviderPing:
            return @"Ping";

        case ADFederationProviderADFSv3:
            return @"ADFSv3";

        case ADFederationProviderADFSv4:
            return @"ADFSv4";
    }
}

- (NSString *)sovereignValue:(ADSovereignEnvironmentType)type
{
    switch (type) {
        case ADEnvironmentTypeGermanCloud:
            return @"AzureGermanyCloud";

        default:
            return @"AzureCloud";
    }
}

- (BOOL)isEqualToRequest:(ADTestConfigurationRequest *)request
{
    if (!request)
    {
        return NO;
    }

    BOOL result = YES;
    result &= self.testUserType == request.testUserType;
    result &= self.federationProviderType == request.federationProviderType;
    result &= self.sovereignEnvironment == request.sovereignEnvironment;
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
    NSUInteger hash = self.testUserType;
    hash ^= self.federationProviderType;
    hash ^= self.sovereignEnvironment;
    hash ^= self.needsMultipleUsers;

    return hash;
}

- (NSURL *)requestURLWithAPIScheme:(NSString *)scheme host:(NSString *)host path:(NSString *)path
{
    NSURLComponents *components = [NSURLComponents new];
    components.scheme = scheme;
    components.host = host;
    components.path = path;

    NSMutableArray *queryItems = [NSMutableArray array];
    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"isFederated" value:[self federatedValue:self.testUserType]]];

    NSString *caValue = [self caValue:self.testUserType];
    if (caValue)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:caValue value:@"True"]];
    }

    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"usertype" value:[self userTypeValue:self.testUserType]]];

    if (self.testUserType == ADUserTypeFederated)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"federationProvider" value:[self federationProviderValue:self.federationProviderType]]];
    }

    [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"AzureEnvironment" value:[self sovereignValue:self.sovereignEnvironment]]];

    if (self.needsMultipleUsers)
    {
        [queryItems addObject:[[NSURLQueryItem alloc] initWithName:@"DisplayAll" value:@"True"]];
    }

    components.queryItems = queryItems;
    NSURL *resultURL = [components URL];
    return resultURL;
}

- (nonnull id)copyWithZone:(nullable NSZone *)zone
{
    ADTestConfigurationRequest *request = [[ADTestConfigurationRequest allocWithZone:zone] init];
    request->_testUserType = _testUserType;
    request->_federationProviderType = _federationProviderType;
    request->_sovereignEnvironment = _sovereignEnvironment;
    request->_needsMultipleUsers = _needsMultipleUsers;
    return request;
}

@end

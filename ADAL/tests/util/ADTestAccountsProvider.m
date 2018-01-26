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
#endif

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
    
    return hash;
}

@end

@implementation ADTestAccountsProvider

- (NSString *)accountTypeToString:(ADTestAccountType)type
{
    NSDictionary *map = @{
                          @(ADTestAccountTypeAAD) : StringName(ADTestAccountTypeAAD),
                          @(ADTestAccountTypePing) : StringName(ADTestAccountTypePing),
                          @(ADTestAccountTypeADFSv3) : StringName(ADTestAccountTypeADFSv3),
                          @(ADTestAccountTypeBlackforest) : StringName(ADTestAccountTypeBlackforest),
                          @(ADTestAccountTypeShib) : StringName(ADTestAccountTypeShib),
                          };
    
    return map[@(type)];
}

- (NSString *)profileTypeToString:(ADTestProfileType)type
{
    NSDictionary *map = @{
                          @(ADTestProfileTypeBasic) : @"Basic",
                          @(ADTestProfileTypeFoci) : @"Foci",
                          @(ADTestProfileTypeSovereign) : @"Sovereign",
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

@end

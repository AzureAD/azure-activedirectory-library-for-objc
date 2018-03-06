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

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, ADTestAccountType)
{
    ADTestAccountTypeAAD,
    ADTestAccountTypeAADMDM,
    ADTestAccountTypePing,
    ADTestAccountTypeADFSv3,
    ADTestAccountTypeBlackforest,
    ADTestAccountTypeShib
};

typedef NS_ENUM(NSInteger, ADTestProfileType)
{
    ADTestProfileTypeBasic,
    ADTestProfileTypeBasicMDM,
    ADTestProfileTypeFoci,
    ADTestProfileTypeSovereign,
};

@interface ADTestAccount : NSObject

@property (nonatomic) NSString *account;
@property (nonatomic) NSString *username;
@property (nonatomic) NSString *password;

@end

@interface ADTestAccountsProvider : NSObject

- (ADTestAccount *)testAccountOfType:(ADTestAccountType)type;
- (NSArray <ADTestAccount *> *)testAccountsOfType:(ADTestAccountType)type;

- (NSDictionary *)testProfileOfType:(ADTestProfileType)type;

@end

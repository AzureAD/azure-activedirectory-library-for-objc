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

/*! ADTestAccountProvider is the federation provider of the AAD account, or none in the case of
 entirely in cloud accounts like WW and Black Forest. They are mutally exclusive of each other. */
typedef NSString *ADTestAccountProvider;
/*! WW is a world wide entirely on-cloud account */
extern ADTestAccountProvider ADTestAccountProviderWW;
/*! Black Forest is an AAD account hosted in the Black Forest sovereign cloud (.de) */
extern ADTestAccountProvider ADTestAccountProviderBlackForest;
/*! A WW account federated using ADFSv2 (these accounts can also be used for on-prem tests) */
extern ADTestAccountProvider ADTestAccountProviderAdfsv2;
/*! A WW account federated using ADFSv3 (these accounts can also be used for on-prem tests) */
extern ADTestAccountProvider ADTestAccountProviderAdfsv3;
/*! A WW account federated using ADFSv4 (these accounts can also be used for on-prem tests) */
extern ADTestAccountProvider ADTestAccountProviderAdfsv4;
/*! A WW account federated using Shibboleth */
extern ADTestAccountProvider ADTestAccountProviderShibboleth;
/*! A WW account federated using Ping */
extern ADTestAccountProvider ADTestAccountProviderPing;

/*! ADTestAccountFeatures are things that can be enabled for a given account, multiple of these can
 be enabled at a time */
typedef NSString *ADTestAccountFeature;
/*! The account has a license and is capable of MDM-ing a device. */
extern ADTestAccountFeature ADTestAccountFeatureMDMEnabled;
/*! The account has a license to be able to use MAM features */
extern ADTestAccountFeature ADTestAccountFeatureMAMEnabled;
/*! The account is capable of registering a device so that it can respond to device auth challenges. */
extern ADTestAccountFeature ADTestAccountFeatureDeviceAuth;
/*! The account is MFA enabled */
extern ADTestAccountFeature ADTestAccountFeatureMFAEnabled;
/*! The account is a guest user */
extern ADTestAccountFeature ADTestAccountFeatureGuestUser;

typedef NSString *ADTestApplication;
extern ADTestApplication ADTestApplicationCloud;
extern ADTestApplication ADTestApplicationOnPremAdfsv2;
extern ADTestApplication ADTestApplicationOnPremAdfsv3;
extern ADTestApplication ADTestApplicationOnPremAdfsv4;
extern ADTestApplication ADTestApplicationRequiresDeviceAuth;
extern ADTestApplication ADTestApplicationRequiresMFA;
extern ADTestApplication ADTestApplicationRequiresMDM;
extern ADTestApplication ADTestApplicationRequiresMAM;

typedef NSString *AppVersion;
extern AppVersion ADAppVersionV1;
extern AppVersion ADAppVersionV2;

@interface ADTestConfigurationRequest : NSObject <NSCopying>

@property (nonatomic) ADTestApplication testApplication;
@property (nonatomic) ADTestAccountProvider accountProvider;
@property (nonatomic) NSArray<ADTestAccountFeature> *accountFeatures;
@property (nonatomic) BOOL needsMultipleUsers;
@property (nonatomic) AppVersion appVersion;

- (NSURL *)requestURLWithAPIPath:(NSString *)apiPath;

@end

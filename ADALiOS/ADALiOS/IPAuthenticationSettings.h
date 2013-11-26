// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

@protocol IPAuthorizationCache;

@interface IPAuthenticationSettings : NSObject

+ (IPAuthenticationSettings *)sharedInstance;

@property (nonatomic) BOOL enableTokenCaching; // Default = YES
@property (nonatomic) BOOL enableSSO;          // Default = YES
@property (nonatomic) BOOL enableFullscreen;   // Default = NO

@property (strong, nonatomic) NSString *clientId;      // Default = Bundle Identifier
@property (strong, nonatomic) NSString *redirectUri;   // Default = <bundle_identifier>://authorize
@property (strong, nonatomic) NSString *platformId;    // Default = nil

#if TARGET_OS_IPHONE
// Resource Path is only use on iPhone/iPad
@property (strong, nonatomic) NSString *resourcePath;  // Default = nil
#endif

@property (strong, nonatomic) id<IPAuthorizationCache> authorizationCache;

@end

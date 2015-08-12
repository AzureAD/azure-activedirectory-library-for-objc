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

#import <Foundation/Foundation.h>

//A helper class for reading the test authorities, usernames, etc.
//Reads the authorities from the TestData.plist file.
@interface ADTestAppSettings : NSObject

+ (ADTestAppSettings*)defaultSettings;

- (id)objectForKey:(NSString*)key;
- (void)setValue:(id)value forKey:(NSString *)key;

- (NSString*)stringForKey:(NSString*)key;
- (NSArray*)arrayForKey:(NSString*)key;
- (NSNumber*)numberForKey:(NSString*)key;
- (BOOL)boolForKey:(NSString*)key;

- (void)populateControl:(UIControl*)control;

// Convenience methods for commonly retrieved values
- (NSString*)authority;
- (NSString*)clientId;
- (NSString*)userId;
- (NSString*)redirectUri;
- (NSString*)extraQueryParams;
- (NSArray*)scopes;
- (NSArray*)additionalScopes;
- (BOOL)validateAuthority;
- (BOOL)fullScreen;
- (int)timeout;

- (void)reset;

@end

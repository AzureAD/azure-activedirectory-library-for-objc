// Created by Boris Vidolov on 1/11/14.
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

#import <ADALiOS/ADPersistentTokenCacheStore.h>

@interface ADKeychainTokenCacheStore : ADPersistentTokenCacheStore

/*! Initializes the token cache store.
 @param: cacheLocation: The library specific key to use for identifying token 
 cache items among the keychain items. Example: "MSOpenTech.ADAL.1.0".
 The initializer returns nil, if cacheLocation is nil or empty.*/
-(id) initWithLocation: (NSString *)cacheLocation;

@end

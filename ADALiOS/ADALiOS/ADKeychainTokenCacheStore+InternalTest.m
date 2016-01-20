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

#import "ADKeychainTokenCacheStore+InternalTest.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"

@implementation ADKeychainTokenCacheStore (InternalTest)

- (void)removeAll:(ADAuthenticationError * __autoreleasing *)error
{
    @synchronized(self)
    {
        NSMutableDictionary* query = [self queryDictionaryForKey:nil userId:nil additional:nil];
        OSStatus status = SecItemDelete((CFDictionaryRef)query);
        [ADKeychainTokenCacheStore checkStatus:status details:@"Failed to remove all" error:error];
        
        NSArray* items = [self allItems:nil];
        if ([items count])
        {
            NSLog(@"!!!!!!!!!!!!!!!!!!!! %d items remaining...", items.count);
        }
    }
}

@end

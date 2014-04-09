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

#import "ADTestTokenCacheStore.h"

@implementation ADTestTokenCacheStore

-(ADTokenCacheStoreItem*) getItemWithKey:(ADTokenCacheStoreKey*)key error: (ADAuthenticationError* __autoreleasing*) error
{
    return nil;
}

-(void) addOrUpdateItem: (ADTokenCacheStoreItem*) item
                  error: (ADAuthenticationError* __autoreleasing*) error
{
}

-(void) removeItemWithKey: (ADTokenCacheStoreKey*) key userId:(NSString *)userId error:(ADAuthenticationError *__autoreleasing *)error
{
    return;
}

-(void) removeAllWithError:(ADAuthenticationError *__autoreleasing *)error
{
    return;
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

-(id) initWithCoder:(NSCoder*) aDecoder
{
    self = [super init];
    return self;
}

-(void) encodeWithCoder:(NSCoder*) aCoder
{
    //Nothing to store.
}

-(ADTokenCacheStoreItem*) getItemWithKey: (ADTokenCacheStoreKey*) key
                                   userId: (NSString *)userId
                                   error:(ADAuthenticationError *__autoreleasing *)error
{
    return nil;
}

-(ADTokenCacheStoreItem*) getItemsWithKey: (ADTokenCacheStoreKey*) key error: (ADAuthenticationError* __autoreleasing*) error
{
    return nil;
}

-(ADTokenCacheStoreItem*) allItemsWithError: (ADAuthenticationError* __autoreleasing*) error;
{
    return nil;
}


@end

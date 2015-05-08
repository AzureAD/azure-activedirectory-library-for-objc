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

#import "NSString+ADHelperMethods.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import "ADBrokerConstants.h"

NSString* const delimiter = @"|";
@implementation ADBrokerKeychainTokenCacheStore
{
    NSString* appKeyHash;
}

-(id) init
{
    
    return [self initWithAppKey:DEFAULT_GUID_FOR_NIL];
}

-(id) initWithAppKey: (NSString *)appKey
{
    if (self = [super initWithGroup:nil])
    {
        appKeyHash = [appKey adComputeSHA256];
    }
    return self;
}

//Given an item key, generates the string key used in the keychain:
-(NSString*) keychainKeyFromCacheKey: (ADTokenCacheStoreKey*) itemKey
{
    return [NSString stringWithFormat:@"%@%@%@",[super keychainKeyFromCacheKey:itemKey],
            delimiter,
            [appKeyHash adBase64UrlEncode]
            ];
}


-(void) removeAllForUser: (NSString*) userId
                   error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
//    @synchronized(self)
//    {
//        ADTokenCacheStoreKey* key = nil;
//        NSArray* allEntries = [self allItemsWithError:error];
//        
//        for(ADTokenCacheStoreItem* item in allEntries)
//        {
//            if([item userInformation] && [NSString adSame:userId toString:item.userInformation.userId])
//            {
//                key = [item extractKeyWithError:error];
//                [self removeItemWithKey:key userId:userId error:error];
//            }
//        }
//    }

    ADAuthenticationError* adError;
    
    @synchronized(self)
    {
        NSMutableDictionary* toDelete = [NSMutableDictionary new];
        //Read all stored keys, then extract the data (full cache item) for each key:
        NSMutableDictionary* all = [self keychainAttributesWithQuery:nil error:&adError];
        if (all)
        {
            for(NSDictionary* attributes in all.allValues)
            {
                ADTokenCacheStoreItem* item = [self readCacheItemWithAttributes:attributes error:&adError];//The error is always logged internally.
                if([item userInformation] && [NSString adSame:userId toString:item.userInformation.userId])
                {
                    [toDelete setObject:attributes forKey:[[NSUUID UUID] UUIDString]];
                }
                else if (adError)
                {
                    break;
                }
            }
        }
        
        if(toDelete.count > 0)
        {
            [self removeWithAttributesDictionaries:toDelete error:&adError];
        }
    }
    
    if (error && adError)
    {
        *error = adError;
    }
}

@end

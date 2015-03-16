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

#import "ADMemoryTokenCacheStore.h"
#import "ADAuthenticationSettings.h"
#import "ADDefaultTokenCacheStorePersistance.h"
#import <libkern/OSAtomic.h>
#import "ADUserInformation.h"
#import "ADTokenCacheStoreItem.h"
#import "ADTokenCacheStoreKey.h"

NSString* const missingUserSubstitute = @"9A1BE88B-F078-4559-A442-35111DFA61F0";
NSString* const multiUserError = @"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used.";

@implementation ADMemoryTokenCacheStore

-(id) init
{
    self = [super init];
    if (self)
    {
        mCache = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE( mCache );
    SAFE_ARC_SUPER_DEALLOC();
}

//The actual method that persists the items in the cache. It is not intended to be thread-safe
//and thread-safety measures should be applied by the caller. This method may be overriden by
//derived classes to implement different means of asymchronous persistence (file system, keychain, some shared storage, etc.)
-(BOOL) persistWithItems: (NSArray*) flatItemsList
                   error: (ADAuthenticationError *__autoreleasing *) error
{
#pragma unused(flatItemsList)
#pragma unused(error)
    [self doesNotRecognizeSelector:_cmd];//Should be overridden by derived classes
    return NO;
}

//Depending on the user information in the item, it may return a unique name,
//to be used in the enclosed dictionary:
+(NSString*) getValidUserFromItem: (ADTokenCacheStoreItem*) item
{
    THROW_ON_NIL_ARGUMENT(item);
    
    if (!item.userInformation || [NSString adIsStringNilOrBlank:item.userInformation.userId])
    {
        return missingUserSubstitute;
    }
    else
    {
        //If the userId is present, just trim the white space and make it lowercase:
        return [item.userInformation.userId adTrimmedString].lowercaseString;
    }
}

-(NSArray*) allItemsWithError:(ADAuthenticationError **)error
{
#pragma unused(error)
    API_ENTRY;
    //Flattens the internal cache, copies all elements:
    NSMutableArray* items = [NSMutableArray new];
    
    @synchronized(mCache)
    {
        for (NSDictionary* innerDict in mCache.allValues)
        {
            for (ADTokenCacheStoreItem* item in innerDict.allValues)
            {
                [items addObject:SAFE_ARC_AUTORELEASE([item copy])];//Copy to prevent modification
            }
        }
    }
    return SAFE_ARC_AUTORELEASE( items );
}

-(void) addOrUpdateItem: (ADTokenCacheStoreItem*) item
                  error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
    RETURN_ON_NIL_ARGUMENT(item);
    
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (key)
    {
        @synchronized(mCache)
        {
            NSMutableDictionary* dictionary = [mCache objectForKey:key];
            if (nil == dictionary)
            {
                //No items for this key, just add the inner dictionary:
                dictionary = SAFE_ARC_AUTORELEASE([NSMutableDictionary new]);
                [mCache setObject:dictionary forKey:key];
            }
            //Now set the object in the inner dictionary, indexed by user:
            [dictionary setObject:SAFE_ARC_AUTORELEASE([item copy])
                           forKey:[self.class getValidUserFromItem:item]];
        }//@synchronized
    }
}

-(void) removeItem: (ADTokenCacheStoreItem*) item
             error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
    RETURN_ON_NIL_ARGUMENT(item);
    
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (key)
    {
        //Note that the userId argument can be nil here, if userInformation or userId
        //is nil. In this case, the userId of the matching items will be ignored:
        [self removeItemWithKey:key
                         userId:item.userInformation.userId
                          error:error];
    }
}

-(void) removeAllWithError:(ADAuthenticationError **)error
{
#pragma unused(error)
    API_ENTRY;
    
    @synchronized(mCache)
    {
        if (mCache.count > 0)
        {
            //Remove and schedule persistence if the cache wasn't already empty:
            [mCache removeAllObjects];
        }
    }
}

-(ADTokenCacheStoreItem*) getItemWithKey: (ADTokenCacheStoreKey*) key
                                  userId: (NSString *)userId
                                   error: (ADAuthenticationError**) error
{
#pragma unused(error)
    API_ENTRY;
    if (!key)
    {
        AD_LOG_WARN(@"getItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey:userId");
        return nil;
    }
    @synchronized(mCache)
    {
        NSDictionary* dictionary = [mCache objectForKey:key];
        
        if (nil == dictionary)
        {
            return nil;//Nothing in the cache.
        }
        
        if (userId == nil)
        {
            NSArray* allValues = dictionary.allValues;
            if (allValues.count > 1)
            {
                ADAuthenticationError* adError =
                [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MULTIPLE_USERS
                                                       protocolCode:nil
                                                       errorDetails:multiUserError];
                if (error)
                {
                    *error = adError;
                }
                return nil;
            }
            else if (allValues.count == 1)
            {
                return SAFE_ARC_AUTORELEASE([[allValues objectAtIndex:0] copy]);
            }
            
            return nil;
        }
        else
        {
            ADTokenCacheStoreItem* item = [dictionary objectForKey:[[userId adTrimmedString] lowercaseString]];
            return SAFE_ARC_AUTORELEASE([item copy]);//May return nil, if item is nil
        }
    }//@synchronized
}

-(void) removeItemWithKey: (ADTokenCacheStoreKey*) key
                   userId: (NSString*) userId
                    error:(ADAuthenticationError **)error
{
#pragma unused(error)
    API_ENTRY;
    
    if (!key)
    {
        AD_LOG_WARN(@"removeItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey:userId");
        return;
    }
    
    @synchronized(mCache)
    {
        NSMutableDictionary* dictionary = [mCache objectForKey:key];
        if (nil == dictionary)
        {
            return;//Not in the cache
        }
        
        if (!userId)
        {
            if (!dictionary.count)
            {
                AD_LOG_WARN(@"Empty inner dictionary", @"The default cache shouldn't store empty dictionary.");
                return;
            }
            
            //Removed all items, regardless of the user. Items exist, else 'dictionary' would have been nil
            //as we do not store empty inner dictionary objects.
            [mCache removeObjectForKey:key];
            return;
        }
        
        NSString* userKey = [[userId adTrimmedString] lowercaseString];
        if ([dictionary objectForKey:userKey] != nil)
        {
            //The item is present, just remove it:
            [dictionary removeObjectForKey:userKey];
            if (!dictionary.count)
            {
                //Avoid storing of empty dictionary:
                [mCache removeObjectForKey:key];
            }
        }
    }
}

-(NSArray*) getItemsWithKey: (ADTokenCacheStoreKey*)key
                      error:(ADAuthenticationError **)error
{
#pragma unused(error)
    API_ENTRY;
    NSMutableArray* array = [NSMutableArray new];
    if (!key)
    {
        AD_LOG_WARN(@"getItemsWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey");
        return SAFE_ARC_AUTORELEASE(array);
    }
    
    @synchronized(mCache)
    {
        NSDictionary* dictionary = [mCache objectForKey:key];
        for (ADTokenCacheStoreItem* item in dictionary.allValues)
        {
            [array addObject:SAFE_ARC_AUTORELEASE([item copy])];
        }
    }
    return SAFE_ARC_AUTORELEASE(array);
}

-(NSArray*) unpersist
{
#if TARGET_OS_IPHONE
    //On the mobile platforms, we need to enforce persistentence, due to the nature of
    //the application lifetimes. We give the option of in-memory, non-persisted cache on the OS X
    //implementations.
    [self doesNotRecognizeSelector:_cmd];//Should be overridden by the derived classes
#endif
    return nil;
}

@end
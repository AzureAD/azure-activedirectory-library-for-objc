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

#import <Security/Security.h>
#import "ADALiOS.h"
#import "ADKeyChainTokenCacheStore.h"
#import "ADTokenCacheStoreItem.h"
#import "NSString+ADHelperMethods.h"
#import "ADTokenCacheStoreKey.h"
#import "ADUserInformation.h"

NSString* const sNilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
NSString* const sDelimiter = @"|";
NSString* const sKeyChainlog = @"Keychain token cache store";
NSString* const sMultiUserError = @"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used.";

const long sKeychainVersion = 1;//will need to increase when we break the forward compatibility

@implementation ADKeychainTokenCacheStore
{
    //Cache store keys:
    id mItemKeyAttributeKey;
    id mUserIdKey;
    
    id mLibraryKey;
    id mClassKey;
    
    id mValueDataKey;
    id mMatchLimitKey;
    id mGroupKey;
    
    //Cache store values:
    id mClassValue;
    NSData* mLibraryValue;
    
    NSString* _sharedGroup;
}

//Shouldn't be called.
-(id) init
{
    [self doesNotRecognizeSelector:_cmd];//Throws
    return nil;
}

//Generates a name for the library items in the keychain (versioned).
//The goal is to ensure that the ADAL reads only its own items with its own version.
-(NSString*) getLibraryPrefix
{
    return [NSString stringWithFormat:@"MSOpenTech.ADAL.%ld", sKeychainVersion];
}

-(id) initWithLocation: (NSString*) cacheLocation
{
    return [self initWithLocation:cacheLocation sharedGroup:nil];
}

-(id) initWithLocation:(NSString *)cacheLocation
           sharedGroup:(NSString *)sharedGroup
{
    if ([NSString isStringNilOrBlank:cacheLocation])
    {
        cacheLocation = [self getLibraryPrefix];
    }
    if (self = [super init])
    {
        //Full key:
        /* The keychain does allow searching for a limited set of attributes only,
         so we need to combine all of the ADTokenCacheStoreKey fields in a single string.*/
        mItemKeyAttributeKey   = (__bridge id)kSecAttrService;
        mUserIdKey             = (__bridge id)kSecAttrAccount;
        
        //Generic setup keys:
        mLibraryKey     = (__bridge id)kSecAttrGeneric;
        mClassKey       = (__bridge id)kSecClass;
        
        mMatchLimitKey  = (__bridge id)kSecMatchLimit;
        
        //Data:
        mValueDataKey   =(__bridge id)kSecValueData;
        
        //Generic setup values:
        mClassValue     = (__bridge id)kSecClassGenericPassword;
        mLibraryValue   = [cacheLocation dataUsingEncoding:NSUTF8StringEncoding];
        
        //Data sharing:
        mGroupKey       = (__bridge id)kSecAttrAccessGroup;
        _sharedGroup    = sharedGroup;

    }
    return self;
}

//Adds the shared group to the attributes dictionary. The method is not thread-safe
-(void) addGroupToDicitonary: (NSMutableDictionary*) dictionary
{
    if (![NSString isStringNilOrBlank:_sharedGroup])
    {
        //Apps are not signed on the simulator, so the shared group doesn't apply there.
#if !(TARGET_IPHONE_SIMULATOR)
        [dictionary setObject:_sharedGroup forKey:mGroupKey];
#endif
    }
}

//Extracts all of the key and user data fields into a single string.
//Used for comparison and verification that the item exists
-(NSString*) extractFullKeyWithDictionary: (NSDictionary*)attributes
{
    THROW_ON_NIL_ARGUMENT(attributes);
    
    return [NSString stringWithFormat:@"%@%@%@",
            [attributes objectForKey:mItemKeyAttributeKey],
            sDelimiter,
            [attributes objectForKey:mUserIdKey]
            ];
}

//Given an item key, generates the string key used in the keychain:
-(NSString*) extractKeyWithItemKey: (ADTokenCacheStoreKey*) itemKey
{
    return [NSString stringWithFormat:@"%@%@%@%@%@",
            [itemKey.authority adBase64UrlEncode], sDelimiter,
            [self.class getAttributeName:itemKey.resource], sDelimiter,
            [itemKey.clientId adBase64UrlEncode]
            ];
}


//Extracts the key text to be used to search explicitly for this item (without the user):
-(NSString*) extractKeyWithItem: (ADTokenCacheStoreItem*)item
                          error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (!key)
    {
        return nil;
    }
    
    return [self extractKeyWithItemKey:key];
}

//Same as extractKeyWithItem, but this time user is included
-(NSString*) extractFullKeyWithItem: (ADTokenCacheStoreItem*)item
                              error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    
    NSString* keyText = [self extractKeyWithItem:item error:error];
    if (!keyText)
    {
        return nil;
    }

    return [NSString stringWithFormat:@"%@%@%@",
                       keyText, sDelimiter, [self.class getAttributeName:item.userInformation.userId]];
}

//Given a set of attributes, deletes the matching keys:
-(void) deleteByAttributes: (NSDictionary*) attributes
                     error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(attributes);
    
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:attributes];
    [query setObject:mClassValue forKey:mClassKey];
    [query setObject:mLibraryValue forKey:mLibraryKey];
    [self addGroupToDicitonary:query];
    
    OSStatus res = SecItemDelete((__bridge CFDictionaryRef)query);
    switch (res)
    {
        case errSecSuccess:
            AD_LOG_VERBOSE_F(sKeyChainlog, @"Successfully removed any items that match: %@", attributes);
            break;
        case errSecItemNotFound:
            AD_LOG_VERBOSE_F(sKeyChainlog, @"No items to remove. Searched for: %@", attributes);
            break;
        default:
            {
                //Couldn't extract the elements:
                NSString* errorDetails = [NSString stringWithFormat:@"Cannot the the items in the keychain. Error code: %ld. Items attempted: %@",
                                          (long)res, attributes];
                ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                         protocolCode:nil
                                                                                         errorDetails:errorDetails];
                if (error)
                {
                    *error = toReport;
                }
            }
            break;
    }
}

//Returns a dictionary with a string cache representing the full key (key & userid).
//The objects of the dictionary are dictionary of keychain attributes that can be used
//directly to update or delete the item.
//Parameter query can be nil. If specified, it adds additional query attributes to filter on.
//Returns nil only in case of error. May return empty dictionary if no items were found.
-(NSMutableDictionary*) getKeysWithQuery: (NSMutableDictionary*) query
                                   error: (ADAuthenticationError* __autoreleasing*)error
{
    if (!query)
    {
        query = [NSMutableDictionary new];
    }
    
    //Add the standard library values:
    [query addEntriesFromDictionary:
    @{
        mClassKey:mClassValue,
        mLibraryKey:mLibraryValue,
          
        //Matching-specific keys
        mMatchLimitKey:(__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes:(__bridge id)kCFBooleanTrue,
    }];
    
    [self addGroupToDicitonary:query];
    
    CFArrayRef all;
    OSStatus res = SecItemCopyMatching((__bridge CFMutableDictionaryRef)query, (CFTypeRef*)&all);
    switch(res)
    {
        case errSecSuccess:
            {
                NSArray* allAttributes = (__bridge_transfer NSArray*)all;
                NSMutableDictionary* toReturn = [[NSMutableDictionary alloc] initWithCapacity:allAttributes.count];
                for(NSDictionary* dictionary in allAttributes)
                {
                    NSString* key = [self extractFullKeyWithDictionary:dictionary];
                    if ([toReturn objectForKey:key] != nil)
                    {
                        AD_LOG_ERROR_F(sKeyChainlog, 0, @"Duplicated keychain cache entry: %@. Attempt to remove them...", key);
                        //Recover by deleting both entries:
                        [toReturn removeObjectForKey:key];
                        [self deleteByAttributes:dictionary error:error];
                    }
                    else
                    {
                        [toReturn setObject:dictionary forKey:key];
                    }
                }
                return toReturn;
            }
            break;
        case errSecItemNotFound:
            {
                AD_LOG_VERBOSE_F(sKeyChainlog, @"No cache items found.");
                return [NSMutableDictionary new];//Empty one
            }
            break;
        default:
            {
                //Couldn't extract the elements:
                NSString* errorDetails = [NSString stringWithFormat:@"Cannot read the items in the keychain. Error code: %ld", (long)res];
                ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                         protocolCode:nil
                                                                                         errorDetails:errorDetails];
                if (error)
                {
                    *error = toReport;
                }
                return nil;
            }
    }
}

//Updates the keychain item. "attributes" parameter should ALWAYS come from previous
//SecItemCopyMatching else the function will fail.
-(void) updateItem: (ADTokenCacheStoreItem*) item
    withAttributes: (NSDictionary*) attributes /* The specific dictionary returned by previous SecItemCopyMatching call */
             error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    THROW_ON_NIL_ARGUMENT(attributes);
    
    NSMutableDictionary* updatedAttributes = [NSMutableDictionary dictionaryWithDictionary:attributes];
    //Required update, as it does not come back from the SecItemCopyMatching:
    [updatedAttributes setObject:mClassValue forKey:mClassKey];//Udpate the class, as it doesn't come explicitly from the previous SecItemMatching call
    [self addGroupToDicitonary:updatedAttributes];
    OSStatus res = SecItemUpdate((__bridge CFMutableDictionaryRef)updatedAttributes,
                                 (__bridge CFDictionaryRef)@{ mValueDataKey:[NSKeyedArchiver archivedDataWithRootObject:item] });
    ADAuthenticationError* toReport = nil;
    switch(res)
    {
        case errSecSuccess:
            //All good
            break;
        case errSecItemNotFound:
            {
                NSString* errorDetails = [NSString stringWithFormat:@"Cannot update the keychain for the item with authority: %@; resource: %@; clientId: %@",
                                         item.authority, item.resource, item.clientId];
                toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                  protocolCode:nil
                                                                  errorDetails:errorDetails];
            }
            break;
        default:
        {
            NSString* errorDetails = [NSString stringWithFormat:@"Cannot update the item in the keychain. Error code: %ld. Item with authority: %@; resource: %@; clientId: %@", (long)res,
                                      item.authority, item.resource, item.clientId];
            toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                              protocolCode:nil
                                                              errorDetails:errorDetails];
        }
    }
    
    if (error && toReport)
    {
        *error = toReport;
    }
}

-(void) addItem: (ADTokenCacheStoreItem*) item
          error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    
    NSString* keyText = [self extractKeyWithItem:item error:error];
    if (!keyText)
    {
        return;
    }
    
    NSMutableDictionary* keychainItem = [NSMutableDictionary dictionaryWithDictionary:@{
        //Generic setup:
        mClassKey:mClassValue,//Encryption
        mLibraryKey:mLibraryValue,//ADAL key
        (__bridge id)kSecAttrIsInvisible:(__bridge id)kCFBooleanTrue, // do not show in the keychain UI
        (__bridge id)kSecAttrAccessible:(__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // do not roam or migrate to other devices
        //Item key:
        mItemKeyAttributeKey: keyText,
        mUserIdKey:[self.class getAttributeName:item.userInformation.userId],
        //Item data:
        mValueDataKey:[NSKeyedArchiver archivedDataWithRootObject:item],
        }];
    [self addGroupToDicitonary:keychainItem];

    OSStatus res = SecItemAdd((__bridge CFMutableDictionaryRef)keychainItem, NULL);
    if (errSecSuccess != res)
    {
        NSString* errorDetails = [NSString stringWithFormat:@"Cannot add a new item in the keychain. Error code: %ld. Item with authority: %@; resource: %@; clientId: %@", (long)res,
                                  item.authority, item.resource, item.clientId];
        ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                 protocolCode:nil
                                                                                 errorDetails:errorDetails];
        if (error)
        {
            *error = toReport;
        }
    }
}

//Extracts the item data from the keychain, based on the "attributes".
//Attributes can either be the result of another bulk get call or set to
//contain the full key of the item.
-(ADTokenCacheStoreItem*) readItemWithAttributes: (NSDictionary*)attributes
                                           error: (ADAuthenticationError* __autoreleasing*)error
{
    THROW_ON_NIL_ARGUMENT(attributes);
    
    //Set up the extraction query:
    NSMutableDictionary* readQuery = [NSMutableDictionary dictionaryWithDictionary:attributes];
    [readQuery addEntriesFromDictionary:@{
    (__bridge id)kSecReturnData:(__bridge id)kCFBooleanTrue, //Return the data
                 mMatchLimitKey:(__bridge id)kSecMatchLimitOne,//Match exactly one
                      mClassKey:mClassValue,//Specify explicitly the class (doesn't come back from previous calls)
    }];
    [self addGroupToDicitonary:readQuery];
    
    CFDataRef data;
    OSStatus res = SecItemCopyMatching((__bridge CFMutableDictionaryRef)readQuery, (CFTypeRef*)&data);
    
    //Process the result
    NSString* errorDetails;
    if (errSecSuccess == res)
    {
        NSData* extracted = (__bridge_transfer NSData*)data;
        ADTokenCacheStoreItem* item = [NSKeyedUnarchiver unarchiveObjectWithData:extracted];
        if ([item isKindOfClass:[ADTokenCacheStoreItem class]])
        {
            //Verify that the item is valid:
            ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
            return key ? item : nil;
        }
        else
        {
            errorDetails = [NSString stringWithFormat:@"The key chain item data does not contain cache item. Attributes: %@", attributes];
        }
    }
    else
    {
        errorDetails = [NSString stringWithFormat:@"Cannot read the data from the keychain. Error code: %ld. Attributes: %@", (long)res, attributes];
    }
    ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                             protocolCode:nil
                                                                             errorDetails:errorDetails];

    if (error)
    {
        *error = toReport;
    }
    return nil;
}

//We should not put nil keys in the keychain. The method substitutes nil with a special GUID:
+(NSString*) getAttributeName: (NSString*)original
{
    return ([NSString isStringNilOrBlank:original]) ? sNilKey : [original adBase64UrlEncode];
}

//Stores the passed items in the group. Does not explicitly remove items that are not there.
//The method is efficient only for bulk operations, as it pulls all items in the dictionary
//first to determine which ones are new and which ones are existing.
-(BOOL) persistWithItems: (NSArray*) flatItemsList
                   error: (ADAuthenticationError *__autoreleasing *) error
{
    ADAuthenticationError* toReport;
    //Get all items which are already in the cache:
    NSMutableDictionary* stored = [self getKeysWithQuery:nil error:&toReport];
    if (!stored)
    {
        //Create an empty one in attempt to recover. The side effect is that we may
        //not delete some items in the cache, but this should not be critical:
        stored = [NSMutableDictionary new];
    }

    //Add or update all passed items:
    for(ADTokenCacheStoreItem* item in flatItemsList)
    {
        NSString* fullKey = [self extractFullKeyWithItem:item error:&toReport];
        if (!fullKey)
        {
            continue;
        }
        NSDictionary* storedAttributes = [stored objectForKey:fullKey];
        if (storedAttributes)
        {
            [stored removeObjectForKey:fullKey];//Clear, as it will be updated.
            //Update item:
            [self updateItem:item withAttributes:storedAttributes error:&toReport];
        }
        else
        {
            //Add the new item:
            [self addItem:item error:&toReport];
        }
    }
  
    if (error && toReport)
    {
        *error = toReport;
    }
    return !toReport;//No error
}

//Internal method: returns a dictionary with all items that match the criteria.
//The keys are the keychain fullkey of the items; the values are the
//keychain attributes as extracted by SecItemCopyMatching. The attributes
//(represented as dictionaries) can be used to obtain the actual token cache item.
//May return nil in case of error.
//The method is not thread-safe.
-(NSDictionary*) getItemAttributesWithKey: (ADTokenCacheStoreKey*) key
                                   userId: (NSString*) userId
                                    error: (ADAuthenticationError* __autoreleasing*) error
{
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:
                                  @{
                                    mItemKeyAttributeKey:[self extractKeyWithItemKey:key],
                                    }];
    
    if (![NSString isStringNilOrBlank:userId])
    {
        [query setObject:userId forKey:mUserIdKey];
    }
    
    return [self getKeysWithQuery:query error:error];
}



//Internal method, used by getItemWithKey and getItemsWithKey public methods.
//The method is thread-safe and always returns a valid object (empty if error
//or no records).
-(NSArray*) getItemsWithKey: (ADTokenCacheStoreKey*) key
                     userId: (NSString*) userId
                  allowMany: (BOOL) allowMany
                      error: (ADAuthenticationError *__autoreleasing *)error
{
    ADAuthenticationError* adError = nil;
    
    if (key)
    {
        @synchronized(self)
        {
            NSDictionary* keyItemAttributes = [self getItemAttributesWithKey:key userId:userId error:&adError];
            if (!keyItemAttributes.count)
            {
                return [NSArray new];//Empty
            }
            if (!allowMany && keyItemAttributes.count != 1)
            {
                adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MULTIPLE_USERS
                                                                 protocolCode:nil
                                                                 errorDetails:sMultiUserError];
            }
            else
            {
                NSMutableArray* array = [[NSMutableArray alloc] initWithCapacity:keyItemAttributes.count];
                for(NSDictionary* attributes in keyItemAttributes.allValues)
                {
                    ADTokenCacheStoreItem* item = [self readItemWithAttributes:attributes
                                                                         error:&adError];
                    if (item)
                    {
                        [array addObject:item];
                    }
                }
                return array;
            }
        }
    }
    else
    {
        adError = [ADAuthenticationError errorFromArgument:key argumentName:@"key"];
    }
    
    if (error && adError)
    {
        *error = adError;
    }
    return [NSArray new];//Always return a valid object
}

//Removes all items, specified by the passed dictionary.
//The dictionary contains item keychain keys (strings) as keys
//and metadata attributes as values (dictionaries). The latter are provided
//exactly as returned by SecItemCopyMatching function.
//keysAndAttributes can be nil.
-(void) removeWithAttributesDictionaries: (NSDictionary*) keysAndAttributes
{
    if (!keysAndAttributes.count)
        return;
    for(NSDictionary* attributes in keysAndAttributes.allValues)
    {
        [self deleteByAttributes:attributes error:nil];
    }
}


//From ADTokenCacheStoring protocol
-(NSArray*) allItems
{
    API_ENTRY;
    @synchronized(self)
    {
        //Read all stored keys, then extract the data (full cache item) for each key:
        NSMutableDictionary* all = [self getKeysWithQuery:nil error:nil];
        if (!all)
        {
            return [NSArray new];//Empty
        }
        NSMutableArray* toReturn = [[NSMutableArray alloc] initWithCapacity:all.count];
        for(NSDictionary* attributes in all.allValues)
        {
            ADTokenCacheStoreItem* item = [self readItemWithAttributes:attributes error:nil];//The error is always logged internally.
            if (item)
            {
                [toReturn addObject:item];
            }
        }
        
        return toReturn;
    }
}

//From ADTokenCacheStoring protocol
-(ADTokenCacheStoreItem*) getItemWithKey: (ADTokenCacheStoreKey*)key
                                  userId: (NSString*) userId
                                   error: (ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;

    NSArray* items = [self getItemsWithKey:key userId:userId allowMany:NO error:error];
    
    return items.count ? items.firstObject : nil;
}

//From ADTokenCacheStoring protocol
-(NSArray*) getItemsWithKey: (ADTokenCacheStoreKey*)key
{
    API_ENTRY;
    
    return [self getItemsWithKey:key userId:nil allowMany:YES error:nil];
}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error: in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
-(void) addOrUpdateItem: (ADTokenCacheStoreItem*) item
                  error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
    @synchronized(self)
    {
        ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
        if (!key)
            return;
        NSDictionary* allAttributes = [self getItemAttributesWithKey:key userId:nil error:error];
        NSString* keychainKey = [self extractFullKeyWithItem:item error:error];
        if (!keychainKey)
            return;
        NSDictionary* attributes = [allAttributes objectForKey:keychainKey];
        if (attributes)
        {
            [self updateItem:item withAttributes:attributes error:error];
        }
        else
        {
            [self addItem:item error:error];
        }
    }
}

//From ADTokenCacheStoring protocol
-(void) removeItemWithKey: (ADTokenCacheStoreKey*) key
                   userId: (NSString*) userId
{
    API_ENTRY;
    @synchronized(self)
    {
        if (!key)
            return;
        NSDictionary* allAttributes = [self getItemAttributesWithKey:key userId:userId error:nil];
        [self removeWithAttributesDictionaries:allAttributes];
    }
}

-(void) removeAll
{
    API_ENTRY;
    @synchronized(self)
    {
        NSDictionary* allAttributes = [self getKeysWithQuery:nil error:nil];
        [self removeWithAttributesDictionaries:allAttributes];
    }
}

-(NSString*) getSharedGroup
{
    return _sharedGroup;
}

-(void) setSharedGroup:(NSString *)sharedGroup
{
    API_ENTRY;
    @synchronized(self)
    {
        if (![NSString adSame:_sharedGroup toString:sharedGroup])
        {
            //Make sure that the state is merged with the group:
            NSArray* allObjects = [self allItems];
            _sharedGroup = sharedGroup;
            [self persistWithItems:allObjects error:nil];
        }
    }
}



@end

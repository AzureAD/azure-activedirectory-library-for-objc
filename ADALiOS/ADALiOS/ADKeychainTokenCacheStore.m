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

#import <Security/Security.h>
#import "ADALiOS.h"
#import "ADKeyChainTokenCacheStore.h"
#import <ADALiOS/ADTokenCacheStoreItem.h>

NSString* const sNilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
NSString* const sDelimiter = @"||";
NSString* const sKeyChainlog = @"Keychain token cache store";

@implementation ADKeychainTokenCacheStore
{
    //Cache store keys:
    id mItemKeyAttributeKey;
    id mUserIdKey;
    
    id mLibraryKey;
    id mClassKey;
    
    id mValueDataKey;
    id mMatchLimitKey;
    
    //Cache store values:
    id mClassValue;
    NSData* mLibraryValue;
}

//Shouldn't be called.
-(id) init
{
    [self doesNotRecognizeSelector:_cmd];//Throws
    return nil;
}

-(id) initWithLocation:(NSString *)cacheLocation
{
    if (self = [super initWithLocation:cacheLocation])
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
        
        //Initialize:
        [self addInitialCacheItems];
    }
    return self;
}

//Extracts all of the key and user data fields into a single string.
//Used for comparison and verification that the item exists
-(NSString*) extractFullKeyWithDictionary:(NSDictionary*)attributes
{
    THROW_ON_NIL_ARGUMENT(attributes);
    
    return [NSString stringWithFormat:@"%@%@%@",
            [attributes objectForKey:mItemKeyAttributeKey],
            sDelimiter,
            [attributes objectForKey:mUserIdKey]
            ];
}

//Ensures that the string does not include delimiter. If it does, the cache may confuse this entry,
//as the delimiter text is used to construct the key. Returns YES, if the string used to generate key
//is valid. Nil string is a valid one.
-(BOOL) validateKeyString:(NSString*)keyString
                     name:(NSString*)name
                    error:(ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(name);
    
    if ([keyString containsString:sDelimiter])
    {
        NSString* message = [NSString stringWithFormat:@"The key chain cannot persist the cache item with %@='%@'. The %@ cannot contain '%@'",
                             name, keyString, name, sDelimiter];
        ADAuthenticationError* toReturn = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE protocolCode:nil errorDetails:message];
        if (error)
        {
            *error = toReturn;
        }
        return NO;
    }
    
    return YES;
}

//Extracts the key text to be used to search explicitly for this item:
-(NSString*) extractKeyWithItem:(ADTokenCacheStoreItem*)item
                          error:(ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (!key ||
        ![self validateKeyString:key.authority name:@"authority" error:error] ||
        ![self validateKeyString:key.resource name:@"resource" error:error] ||
        ![self validateKeyString:key.clientId name:@"clientId" error:error])
    {
        return nil;
    }
    
    return [NSString stringWithFormat:@"%@%@%@%@%@",
            key.authority, sDelimiter,
            [self.class getAttributeName:key.resource], sDelimiter,
            key.clientId
            ];
}

-(NSString*) extractFullKeyWithItem:(ADTokenCacheStoreItem*)item
                              error:(ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    
    NSString* keyText = [self extractKeyWithItem:item error:error];
    if (!keyText || ![self validateKeyString:item.userInformation.userId name:@"userId" error:error])
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

//Returns a dictionary with a string cache representing the full key (key & userid)
//The objects of the dictionary are dictionary of keychain attributes that can be used directly to update or delete the item.
-(NSMutableDictionary*) getAllStoredKeys:(ADAuthenticationError* __autoreleasing*)error
{
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:
    @{
        mClassKey:mClassValue,
        mLibraryKey:mLibraryValue,
          
        //Matching-specific keys
        mMatchLimitKey:(__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes:(__bridge id)kCFBooleanTrue,
    }];
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
                AD_LOG_VERBOSE_F(sKeyChainlog, @"No cache items found for the key %@", self.cacheLocation);
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
    withAttributes: (NSDictionary*) attributes /* Explicitly and dictionary returned by previous SecItemCopyMatching call */
             error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(item);
    THROW_ON_NIL_ARGUMENT(attributes);
    
    NSMutableDictionary* updatedAttributes = [NSMutableDictionary dictionaryWithDictionary:attributes];
    //Required update, as it does not come back from the SecItemCopyMatching:
    [updatedAttributes setObject:mClassValue forKey:mClassKey];//Udpate the class, as it doesn't come explicitly from the previous SecItemMatching call
    OSStatus res = SecItemUpdate((__bridge CFMutableDictionaryRef)updatedAttributes,
                                 (__bridge CFDictionaryRef)@{ mValueDataKey:[NSKeyedArchiver archivedDataWithRootObject:item] });
    switch(res)
    {
        case errSecSuccess:
            //All good
            break;
        case errSecItemNotFound:
            {
                NSString* errorDetails = [NSString stringWithFormat:@"Cannot update the keychain for the item with authority: %@; resource: %@; clientId: %@",
                                         item.authority, item.resource, item.clientId];
                ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                         protocolCode:nil
                                                                                         errorDetails:errorDetails];
                if (error)
                {
                    *error = toReport;
                }
            }
            break;
        default:
        {
            NSString* errorDetails = [NSString stringWithFormat:@"Cannot update the item in the keychain. Error code: %ld. Item with authority: %@; resource: %@; clientId: %@", (long)res,
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
    
    NSDictionary* keychainItem = @{
        //Generic setup:
        mClassKey:mClassValue,//Encryption
        mLibraryKey:mLibraryValue,//ADAL key
        (__bridge id)kSecAttrIsInvisible:(__bridge id)kCFBooleanTrue, // do not show in the keychain UI
        (__bridge id)kSecAttrAccessible:(__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly, // do not roam or migrate to other devices
        //Item key:
        mItemKeyAttributeKey: keyText,
        mUserIdKey:[self.class getAttributeName:item.userInformation.userId],
        //Item data:
        mValueDataKey:[NSKeyedArchiver archivedDataWithRootObject:item],
        };

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
    [readQuery setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];//Return the data
    [readQuery setObject:(__bridge id)kSecMatchLimitOne forKey:mMatchLimitKey];//Match exactly one
    [readQuery setObject:mClassValue forKey:mClassKey];//Specify explicitly the class (doesn't come back from previous calls)
    
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
    return ([NSString isStringNilOrBlank:original]) ? sNilKey : original;
}

//Overrides the parent class method, ensures that the keychain contains the same value as the memory cache:
-(BOOL) persistWithItems: (NSArray*) flatItemsList
                   error: (ADAuthenticationError *__autoreleasing *) error
{
    THROW_ON_NIL_ARGUMENT(flatItemsList);
    
    ADAuthenticationError* toReport;
    //Get all items which are already in the cache:
    NSMutableDictionary* stored = [self getAllStoredKeys:&toReport];
    if (!stored)
    {
        //Create an empty one in attempt to recover. The side effect is that we may
        //not delete some items in the cache, but this should not be critical:
        stored = [NSMutableDictionary new];
    }

    //Add or update all passed items. Remove them from the "stored" list:
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
    
    //Now remove all items that are not present in the new set:
    for(NSDictionary* attributes in stored.allValues)
    {
        [self deleteByAttributes:attributes error:&toReport];
    }
    
    if (error)
    {
        *error = toReport;
    }
    return !toReport;//No error
}

//Overrides the parent class method, reads all cache items.
-(NSArray*) unpersist
{
    //Read all stored keys, then extract the data (full cache item) for each key:
    NSMutableDictionary* all = [self getAllStoredKeys:nil];
    if (!all)
    {
        return nil;//the error is already logged.
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

@end

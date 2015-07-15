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
#import "ADKeychainTokenCacheStore.h"
#import "ADTokenCacheStoreItem.h"
#import "NSString+ADHelperMethods.h"
#import "ADTokenCacheStoreKey.h"
#import "ADUserInformation.h"
#import "ADKeychainQuery.h"

NSString* const sNilKey = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";//A special attribute to write, instead of nil/empty one.
NSString* const sDelimiter = @"|";
NSString* const sKeyChainlog = @"Keychain token cache store";
NSString* const sMultiUserError = @"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used.";
NSString* const sKeychainSharedGroup = @"com.microsoft.adalcache";

const long sKeychainVersion = 1;//will need to increase when we break the forward compatibility

static dispatch_queue_t s_keychainQueue = NULL;
static const char * s_keychainQueueLabel = "ADAL.keychain";

static void adkeychain_dispatch_if_needed(dispatch_block_t block)
{
    const char* szLabel = dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL);
    if (strcmp(s_keychainQueueLabel, szLabel) == 0)
    {
        block();
    }
    else
    {
        dispatch_sync(s_keychainQueue, block);
    }
}


@implementation ADKeychainTokenCacheStore
{
    NSString* _sharedGroup;
}

- (id)init
{
    // Shouldn't be called.
    return [self initWithGroup:sKeychainSharedGroup];
}

- (id)initWithGroup:(NSString *)sharedGroup
{
    if (!(self = [super init]))
    {
        return nil;
    }

    _sharedGroup = sharedGroup;
    
    return self;
}

+ (void)initialize
{
    // +initialize is called on the first use of this class. Create a concurrent queue to do all keychain operations.
    // While it's still possible (albeit unlikely) that another process could slip in and alter the keychain underneath
    // us while we're running, this will keep the same process from stomping on itself.
    
    s_keychainQueue = dispatch_queue_create(s_keychainQueueLabel, DISPATCH_QUEUE_CONCURRENT);
}

+ (BOOL)handleKeychainCode:(OSStatus)errCode
                 operation:(NSString*)operation
                     error:(ADAuthenticationError* __autoreleasing *)error
{
    if (error)
    {
        *error = nil;
    }
    
    if (errCode == errSecSuccess)
    {
        NSString* log = [NSString stringWithFormat:@"ADAL Keychain \"%@\" operation succeeded.", operation];
        AD_LOG_INFO(log, nil);
        return NO;
    }
    
    if (errCode == errSecItemNotFound)
    {
        // If we didn't find anything we don't log it as an error as there's usually a number of cases where that's expected
        // and we don't want to send up red herrings.
        NSString* log = [NSString stringWithFormat:@"ADAL Keychain \"%@\" found no matching items.", operation];
        AD_LOG_INFO(log, nil);
        return YES;
    }
    
    NSString* log = [NSString stringWithFormat:@"ADAL Keychain \"%@\" operation failed with error code %d.", operation, (int)errCode];
    // Creating the ADError object will cause the error to get logged.
    ADAuthenticationError* adError = [ADAuthenticationError errorFromKeychainError:errCode errorDetails:log];
    
    if (error)
    {
        *error = adError;
    }
    
    return YES;
}

/*! Log operations that result in storing or reading cache item */
- (void)logItem:(ADTokenCacheStoreItem*)item
        message:(NSString*)additionalMessage
{
    AD_LOG_VERBOSE_F(sKeyChainlog, @"%@. scopes: %@ Access token hash: %@; Refresh token hash: %@", additionalMessage, item.scopes, [ADLogger getHash:item.accessToken], [ADLogger getHash:item.refreshToken]);
}

#pragma mark Keychain Helper Methods

- (OSStatus)copyDictionary:(CFMutableDictionaryRef *)outKeychainItems
                    userId:(NSString*)userId
                     error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!outKeychainItems)
    {
        ADAuthenticationError* adError = [ADAuthenticationError invalidArgumentError:@"outKeychainItems must be provided"];
        if (error)
        {
            *error = adError;
        }
        return errSecParam;
    }
    
    *outKeychainItems = NULL;
    
    ADKeychainQuery* retrieveQuery = [[ADKeychainQuery alloc] init];
    [retrieveQuery setAccessGroup:_sharedGroup];
    [retrieveQuery setUserId:userId];
    [retrieveQuery setCopyData];
    
    CFTypeRef data = NULL;
    OSStatus err = SecItemCopyMatching([retrieveQuery queryDictionary], &data);
    if (![ADKeychainTokenCacheStore handleKeychainCode:err operation:@"removeItemWithKey" error:error])
    {
        return err;
    }
    
    CFErrorRef cfError = NULL;
    // If this keychain entry is bad, we might as well zap the whole thing, rather then let the user get stuck in a bad, unrecoverable state
    CFMutableDictionaryRef cfmdKeychainItem = (CFMutableDictionaryRef)CFPropertyListCreateWithData(NULL, (CFDataRef)data, kCFPropertyListMutableContainers, NULL, &cfError);
    if (!cfmdKeychainItem)
    {
        ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:(__bridge NSError*)cfError
                                                                    errorDetails:@"failure deserializing data from keychain."];
        if (error)
        {
            *error = adError;
        }
        
        return errSecDecode;
    }
    
    *outKeychainItems = cfmdKeychainItem;
    return errSecSuccess;
}
- (void)writeDictionary:(CFDictionaryRef)dictionary
                 userId:(NSString*)userId
{
    
    CFErrorRef cfError = NULL;
    CFDataRef data = CFPropertyListCreateData(NULL, dictionary, kCFPropertyListBinaryFormat_v1_0, 0, &cfError);
    
    if (data == NULL)
    {
        return;
    }
    
    ADKeychainQuery* writeQuery = [[ADKeychainQuery alloc] init];
    [writeQuery setUserId:userId];
    
    const void * keys[] = { kSecAttrGeneric };
    const void * values[] = { data };
    
    // Create an attributes dictionary for the generic data on the specified item
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    // Write it out ot keychain
    SecItemUpdate([writeQuery queryDictionary], attributes);
    
    CFRelease(attributes);
}

- (void)removeAllForUser:(NSString*)userId
                   error:(ADAuthenticationError* __autoreleasing*)error
{
    adkeychain_dispatch_if_needed(^{
        ADKeychainQuery* keychainQuery = [[ADKeychainQuery alloc] init];
        [keychainQuery setAccessGroup:_sharedGroup];
        [keychainQuery setUserId:userId];
        OSStatus err = SecItemDelete([keychainQuery queryDictionary]);
        [ADKeychainTokenCacheStore handleKeychainCode:err operation:@"removeAllForUser" error:error];
    });
}



#pragma mark ADTokenCacheStoring methods

- (ADTokenCacheStoreItem*)getItemWithKey:(ADTokenCacheStoreKey*)key
                                   error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    
    __block ADTokenCacheStoreItem* item = nil;
    
    adkeychain_dispatch_if_needed(^{
        CFMutableDictionaryRef cfmdKeychainItems = NULL;
        OSStatus err = [self copyDictionary:&cfmdKeychainItems
                                userId:[key userCacheKey]
                                 error:error];
        
        if (err != errSecSuccess)
        {
            return;
        }
        
        CFDataRef data = CFDictionaryGetValue(cfmdKeychainItems, (__bridge const void *)([key key]));
        if (!data)
        {
            return;
        }
        
        item = [NSKeyedUnarchiver unarchiveObjectWithData:(__bridge NSData *)(data)];
    });
    
    
    return item;
}

/*!
 Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 
 @param error    in case of an error, if this parameter is not nil, it will be filled with
 the error details.
 */
- (void)addOrUpdateItem:(ADTokenCacheStoreItem*)item
                  error:(ADAuthenticationError* __autoreleasing*)error
{
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (!key)
    {
        return;
    }
    
    adkeychain_dispatch_if_needed(^{
        CFMutableDictionaryRef cfmdKeychainDict = NULL;
        OSStatus err = [self copyDictionary:&cfmdKeychainDict
                                     userId:[item userCacheKey]
                                      error:error];
        
        if (err == errSecItemNotFound)
        {
            cfmdKeychainDict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        }
        else if (err != errSecSuccess)
        {
            return;
        }
        
        CFDictionarySetValue(cfmdKeychainDict, (__bridge const void *)([key key]), (__bridge const void *)([NSKeyedArchiver archivedDataWithRootObject:item]));
    });
}

- (void)removeItemWithKey:(ADTokenCacheStoreKey*)key
                    error:(ADAuthenticationError* __autoreleasing* )error
{
    API_ENTRY;
    
    if (!key)
    {
        ADAuthenticationError* adError = [ADAuthenticationError invalidArgumentError:@"removeItemWithKey requires a key to be specified."];
        if (error)
        {
            *error = adError;
        }
        return;
    }
    
    adkeychain_dispatch_if_needed(^{
        CFMutableDictionaryRef cfmdKeychainItem = NULL;
        OSStatus err = [self copyDictionary:&cfmdKeychainItem
                                userId:[key userCacheKey]
                                 error:error];
        if (err == errSecDecode)
        {
            [self removeAllForUser:[key userCacheKey]
                             error:nil];
            return;
        }
        
        // If the item we're looking for isn't even in the dictionary then we're already done.
        if (!CFDictionaryContainsKey(cfmdKeychainItem, (__bridge const void *)([key key])))
        {
            CFRelease(cfmdKeychainItem);
            return;
        }
        
        // Remove the item from the dictionary
        CFDictionaryRemoveValue(cfmdKeychainItem, (__bridge const void *)([key key]));
        
        // And write it back out to keychain
        [self writeDictionary:cfmdKeychainItem userId:[key userCacheKey]];
    });
}

- (void)removeAllWithError:(ADAuthenticationError *__autoreleasing *)error
{
    adkeychain_dispatch_if_needed(^{
        ADKeychainQuery* keychainQuery = [[ADKeychainQuery alloc] init];
        [keychainQuery setAccessGroup:_sharedGroup];
        OSStatus err = SecItemDelete([keychainQuery queryDictionary]);
        [ADKeychainTokenCacheStore handleKeychainCode:err operation:@"removeAll" error:error];
    });
}

@end

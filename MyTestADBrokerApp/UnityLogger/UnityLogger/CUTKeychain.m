/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: This file abstracts the calls to the keychain
 
 Owner: izikl
 Created: 05/22/2014
 */

#import "CUTKeychain.h"
#include "CUTConstants.h"
#import "CUTLibrary.h"
#import "CUTTrace.h"

// holds the bundle seed ID.
static NSString *bundleSeedID;

@implementation CUTKeychain

//
// keychainItemWithAccessGroup:serviceAttribute:accountAttribute:error:
//
+ (id)keychainItemWithAccessGroup:(NSString *)accessGroup
                       serviceAttribute:(NSString *)service
                       accountAttribute:(NSString *)account
                                  error:(NSError **)error
{   
    CUTAssertAndReturnValueIfFalse(error != nil, nil, kCUTUtilityDomain, @"error is nil")
    
    // Validate parameters
    *error = [CUTKeychain validateParametersAccessGroup:accessGroup service:service account:account];
    if (*error != nil) return nil;
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Query keychain for key {accessGroup: %@, service: %@, account: %@}", accessGroup, service, [CUTKeychain traceableStringForAccount:account]);
    
    // Prepare Search query
    NSMutableDictionary *searchDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                      (__bridge id)(kSecClassGenericPassword),      (__bridge id)kSecClass,
                                      service,                                      (__bridge id)kSecAttrService,
                                      account,                                      (__bridge id)kSecAttrAccount,
                                      nil];
    
    // Add access group
    [self setAccessGroup:accessGroup inDictionary:searchDictionary];
    
    // Query KeyChain
    OSStatus status;
    NSData *result = [[self class] keychainItemFromSearchDictionary:searchDictionary
                                                             status:&status];
    
    // Check Errors (Consider NotFoundError as success)
    if ( status != errSecSuccess && status != errSecItemNotFound)
    {
        NSString *errMsg = [NSString stringWithFormat:@"Failed to fetch a value from the Keychain. error Code (SecBase.h): %d", (int)status];
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        *error = [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorGeneric
                                message:errMsg];
        
        return nil;
    }
    
    NSString *successMessage = status != errSecItemNotFound ? @"value fetched successfully from keychain" : @"value was not found in keychain";
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"%@", successMessage);
    *error = nil;
    
    return result ? [[self class] unarchiveData:result key:account] : result;
}

//
// addData:toKeychainWithAccessGroup:serviceAttribute:accountAttribute:
//
+ (NSError *)           addData:(id)data
      toKeychainWithAccessGroup:(NSString *)accessGroup
               serviceAttribute:(NSString *)service
               accountAttribute:(NSString *)account
{
    CUTAssert(data != nil, kCUTUtilityDomain, @"data is nil")
    
    // Validate parameters
    NSError *pErr = [CUTKeychain validateParametersAccessGroup:accessGroup service:service account:account data:data];
    if (pErr != nil) return pErr;
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"adding item to key chain. {accessGroup: %@, service: %@, account: %@}", accessGroup, service, [CUTKeychain traceableStringForAccount:account]);
    
    // Construct the Keychain attributes
    NSMutableDictionary *attributes = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                (__bridge id)(kSecClassGenericPassword),         (__bridge id)kSecClass,
                                service,                                         (__bridge id)kSecAttrService,
                                account,                                         (__bridge id)kSecAttrAccount,
                                [[self class] archiveData:data withKey:account], (__bridge id)kSecValueData,
                                (__bridge id)kSecAttrAccessibleWhenUnlocked,     (__bridge id)kSecAttrAccessible,
                                nil];

    
    // Add access group
    [self setAccessGroup:accessGroup inDictionary:attributes];
    
    // Adding item to keychain
    OSStatus status = [[self class] addKeychainItemWithAttributesDictionary:attributes];
    
    // Error: Duplicate Key
    if ( status == errSecDuplicateItem )
    {
        NSString *errMsg = @"Failed to add a value to the Keychain becuase key already exists";
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorKeyAlreadyExists
                                message:errMsg];
    }
    
    // Error: Generic Error
    if ( status != errSecSuccess )
    {
        NSString *errMsg = [NSString stringWithFormat:@"Failed to add a value to the Keychain. error Code (SecBase.h): %d", (int)status];
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorGeneric
                                message:errMsg];
    }
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Value added to key chain successfully");
    return nil;
}

//
// updateData:inKeychainWithAccessGroup:serviceAttribute:accountAttribute:
//
+ (NSError *)        updateData:(id)data
      inKeychainWithAccessGroup:(NSString *)accessGroup
               serviceAttribute:(NSString *)service
               accountAttribute:(NSString *)account
{
    CUTAssert(data != nil, kCUTUtilityDomain, @"data is nil")
    
    // Validate parameters
    NSError *pErr = [CUTKeychain validateParametersAccessGroup:accessGroup service:service account:account data:data];
    if (pErr != nil) return pErr;
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"updating item in the key chain. {accessGroup: %@, service: %@, account: %@}", accessGroup, service, [CUTKeychain traceableStringForAccount:account]);
    
    // Construct the Keychain attributes
    NSMutableDictionary *attributesToQuery = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                       (__bridge id)(kSecClassGenericPassword),       (__bridge id)kSecClass,
                                       service,                                       (__bridge id)kSecAttrService,
                                       account,                                       (__bridge id)kSecAttrAccount,
                                       nil];
    
    // Add access group
    [self setAccessGroup:accessGroup inDictionary:attributesToQuery];
    
    NSDictionary *attributesToUpdate = [NSDictionary dictionaryWithObjectsAndKeys:
                                        [[self class] archiveData:data withKey:account], (__bridge id)kSecValueData,
                                        nil];
    
    // Update item in the keychain
    OSStatus status = [[self class] updateKeychainItemWithSearchDictionary:attributesToQuery
                                                       andUpdateDictionary:attributesToUpdate];

    // Error: Duplicate Key
    if ( status == errSecItemNotFound )
    {
        NSString *errMsg = @"Failed to update a value in the keychain since the key doesn't exists.";
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorValueNotFound
                                message:errMsg];
    }
    
    // Error: Generic Error
    if ( status != errSecSuccess )
    {
        NSString *errMsg = [NSString stringWithFormat:@"Failed to update a value in the keychain. error Code (SecBase.h): %d", (int)status];
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorGeneric
                                message:errMsg];
    }
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Value updated in keychain successfully");
    return nil;
}

//
// updateOrAddData:toKeychainWithAccessGroup:serviceAttribute:accountAttribute:
//
+ (NSError *)   updateOrAddData:(id)data
      toKeychainWithAccessGroup:(NSString *)accessGroup
               serviceAttribute:(NSString *)service
               accountAttribute:(NSString *)account
{
    CUTAssertAndReturnValueIfFalse(data != nil, nil, kCUTUtilityDomain, @"data is nil")
    
    // Validate parameters
    NSError *pErr = [CUTKeychain validateParametersAccessGroup:accessGroup service:service account:account data:data];
    if (pErr != nil) return pErr;
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"updating or adding item to the key chain. {accessGroup: %@, service: %@, account: %@}", accessGroup, service, [CUTKeychain traceableStringForAccount:account]);
    
    // Query key chain
    NSError *error = nil;
    NSData *oldKeychainItem = [CUTKeychain keychainItemWithAccessGroup:accessGroup
                                                      serviceAttribute:service
                                                      accountAttribute:account
                                                                 error:&error];
    
    if (error != nil)
    {
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorGeneric
                                message:@"Failed to query the keychain (to check if value exists) before updating or adding a keychain item."];
    }
    
    if (oldKeychainItem)
    {
        // Update Keychain
        error = [CUTKeychain      updateData:data
                   inKeychainWithAccessGroup:accessGroup
                            serviceAttribute:service
                            accountAttribute:account];
    }
    else
    {
        // Add to keychain
        error = [CUTKeychain         addData:data
                   toKeychainWithAccessGroup:accessGroup
                            serviceAttribute:service
                            accountAttribute:account];
    }
    
    if (error)
    {
        NSString *errMsg = @"Failed to add/update a value from the keychain";
        CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTKeychainErrorGeneric
                                message:errMsg];
    }
    
    return nil;
}

//
// bundleSeedID
//
+ (NSString *)bundleSeedID
{
    if (bundleSeedID == nil) {
        @synchronized(bundleSeedID) {
            if (bundleSeedID == nil) {
                // create search query
                NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                              (__bridge id)kSecClassGenericPassword,   (__bridge id)kSecClass,
                                              [CUTKeychain bundleSeedIDAccount],       (__bridge id)kSecAttrAccount,
                                              @"",                                     (__bridge id)kSecAttrService,
                                              nil];
                
                // Search for item in keychain
                NSDictionary *attributes = nil;
                OSStatus status;
                attributes = [CUTKeychain keychainItemAttributesFromSearchDictionary:query status:&status];
                
                // if not found in keychain, add it.
                if (status == errSecItemNotFound)
                {
                    status = [CUTKeychain addKeychainItemWithAttributesDictionary:query
                                                              addedItemAttributes:&attributes];
                    
                    if (status != errSecSuccess)
                    {
                        NSString *errMsg = [NSString stringWithFormat:@"Failed to add bundleSeedID to the keychain. error Code (SecBase.h): %d", (int)status];
                        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
                        return nil;
                    }
                }
                
                if (status != errSecSuccess)
                {
                    NSString *errMsg = [NSString stringWithFormat:@"Failed to read bundleSeedID from the keychain. error Code (SecBase.h): %d", (int)status];
                    CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
                    return nil;
                }
                
                NSString *accessGroup = [attributes objectForKey:(__bridge id)kSecAttrAccessGroup];
                
                if (accessGroup == nil)
                {
                    CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"Failed to read access group from bundleSeedID's attributes");
                    return nil;
                }
                
                NSArray *components = [accessGroup componentsSeparatedByString:@"."];
                bundleSeedID = [[components objectEnumerator] nextObject];
                CUTTrace(CUTTraceLevelInfo, kCUTUtilityDomain, @"bundleSeedID is: %@", bundleSeedID);
            }
        }
    }
    
    return bundleSeedID;
}

//
// keychainCertificateWithAccessGroup:serviceAttribute:serialNumber:error:
//
+ (NSData*)keychainCertificateWithAccessGroup:(NSString *)accessGroup
                             serviceAttribute:(NSString *)service
                                 serialNumber:(NSData *)serialNumber
                                        error:(NSError **)error
{
    CUTAssertAndReturnValueIfFalse(error != nil, nil, kCUTUtilityDomain, @"error is nil");
    
    // Validate parameters
    if (serialNumber == nil)
    {
        NSString *errMsg =  @"serialNumber parameter is nil";
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        *error = [NSError errorWithDomain:kCUTUtilityDomain
                                     code:CUTErrorInvalidArgument
                                  message:errMsg];
        return nil;
    }
    *error = [CUTKeychain validateAccessGroup:accessGroup];
    if (*error != nil)
    {
        return nil;
    }
    
    *error = [CUTKeychain validateServiceAttribute:service];
    if (*error != nil)
    {
        return nil;
    }
    
    //Read certificate from keychain
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Query keychain for Certificate with key {accessGroup: %@, service: %@, serial#: %@}", accessGroup, service, serialNumber);
    
    CFDataRef serialNumberRef = (__bridge CFDataRef)serialNumber;
    
    CFArrayRef items;
    NSMutableDictionary *certAttr = [[NSMutableDictionary alloc] init];
    [certAttr setObject:(__bridge id)(kSecClassCertificate) forKey:(__bridge id)kSecClass];
    [certAttr setObject:(__bridge id)(kSecMatchLimitAll) forKey:(__bridge id<NSCopying>)(kSecMatchLimit)];
    [certAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    [certAttr setObject:(__bridge id)(serialNumberRef) forKey:(__bridge id<NSCopying>)(kSecAttrSerialNumber)];
    [self setAccessGroup:accessGroup inDictionary:certAttr];
    
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)certAttr, (CFTypeRef *) &items);
    
    if (err != noErr)
    {
        
        NSString *errMsg = [NSString stringWithFormat:@"Failed to fetch certificate from the Keychain. error Code (SecBase.h): %d", (int)err];
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        *error = [NSError errorWithDomain:kCUTUtilityDomain
                                     code:CUTKeychainErrorGeneric
                                  message:errMsg];
        return nil;
    }
    
    NSData* certData = nil;
    
    if (CFArrayGetCount(items) >= 1 )
    {
        CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"%@", @"certificate fetched successfully from keychain");
        *error = nil;
        
        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(items, 0);
        certData = (NSData *) CFBridgingRelease(SecCertificateCopyData(cert));
    }
    else
    {
        NSString *errMsg = [NSString stringWithFormat:@"Failed to fetch certificate from the Keychain. Zero certificates returned."];
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        *error = [NSError errorWithDomain:kCUTUtilityDomain
                                     code:CUTKeychainErrorValueNotFound
                                  message:errMsg];
    }    CFRelease(items);
    return certData;
}


#pragma mark - private static methods

//
// setAccessGroup:inDictionary:
//
+ (void)setAccessGroup:(NSString *)accessGroup inDictionary:(NSMutableDictionary *)searchDictionary
{
#if !TARGET_IPHONE_SIMULATOR
    // access group is not supported on simulator
    if (accessGroup)
    {
        NSString *accessGroupWithBundleSeed = [NSString stringWithFormat:@"%@.%@", [CUTKeychain bundleSeedID], accessGroup];
        
        [searchDictionary setObject:accessGroupWithBundleSeed
                             forKey:(__bridge id)kSecAttrAccessGroup];
    }
#endif
}

//
// keychainItemFromSearchDictionary:status:
// a wrapper around SecItemCopyMatching (Apple's API to search in the keychain). Also handles bridging from CF.
// Returns the keychain item if found otherwise returns nil. To fetch keychain item's attributes use
// keychainItemAttributesFromSearchDictionary:status:
// Mainly used as a test hook. In unittests this method will be mocked
//
+ (NSData *)keychainItemFromSearchDictionary:(NSMutableDictionary *)searchDictionary
                                      status:(OSStatus *)status
{
    CUTAssertAndReturnValueIfFalse(status != nil, nil, kCUTUtilityDomain, @"error pointer was nil.")
    
    // Set SecItemCopyMatching's to return the item itself (instead of the item's attributes)
    [searchDictionary setObject:(__bridge id)kCFBooleanTrue
                         forKey:(__bridge id)kSecReturnData];
    
    NSDictionary *dictionary = (NSDictionary *)searchDictionary;
    CFTypeRef resultAsTypeRef = nil;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef)dictionary,
                                  (CFTypeRef *)&resultAsTypeRef);
    
    return (__bridge_transfer NSData *)resultAsTypeRef;
}

//
// keychainItemAttributesFromSearchDictionary:error:
// a wrapper around SecItemCopyMatching (Apple's API to search in the keychain). Also handles bridging from CF.
// Returns the keychain item's attributes if item exists in keychain otherwise returns nil.
// To fetch the keychain item itself use keychainItemFromSearchDictionary:status:
// Mainly used as a test hook. In unittests this method will be mocked.
//
+ (NSDictionary *)keychainItemAttributesFromSearchDictionary:(NSMutableDictionary *)searchDictionary
                                                status:(OSStatus *)status
{
    CUTAssertAndReturnValueIfFalse(status != nil, nil, kCUTUtilityDomain, @"error pointer was nil.")
    
    NSDictionary *result = nil;
    
    // Set the SecItemCopyMatching's to return the item's attributes (instead of the data itself)
    [searchDictionary setObject:(__bridge id)kCFBooleanTrue
                         forKey:(__bridge id)kSecReturnAttributes];
    
    CFTypeRef resultAsTypeRef = nil;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary,
                                  (CFTypeRef *)&resultAsTypeRef);
    
    if (*status == errSecSuccess)
    {
        // move ownership of this dictionary to ARC.
        result = (__bridge_transfer NSDictionary *)resultAsTypeRef;
    }
    
    return result;
}

//
// addKeychainItemWithAttributesDictionary:error:
// private utility to do the actuall call to the keychain. Mainly used as a test hook.
// In unittests this method will be mocked.
//
+ (OSStatus)addKeychainItemWithAttributesDictionary:(NSDictionary *)attributesWithDataDictionary
{
     return SecItemAdd((__bridge CFDictionaryRef)attributesWithDataDictionary, NULL);
}

//
// addKeychainItemWithAttributesDictionary:error:
// A wrapper around SecItemAdd. Adds an item to the keychain. Also handled briding to and from CF.
// private utility to do the actuall call to the keychain. Mainly used as a test hook.
// In unittests this method will be mocked.
//
+ (OSStatus)addKeychainItemWithAttributesDictionary:(NSDictionary *)attributesWithDataDictionary
                                addedItemAttributes:(NSDictionary **)addedItemAttributes
{
    CUTAssertAndReturnValueIfFalse(addedItemAttributes != nil, errSecParam, kCUTUtilityDomain, @"addedItemAttributes is nil");

    CFDictionaryRef result = nil;
    *addedItemAttributes = nil;
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributesWithDataDictionary, (CFTypeRef *)&result);
    
    if (status == errSecSuccess)
    {
        *addedItemAttributes = (__bridge_transfer NSDictionary *)result;
    }
    
    return status;
}

//
// updateKeychainItemWithSearchDictionary:error:
// private utility to do the actuall call to the keychain. Mainly used as a test hook.
// In unittests this method will be mocked.
//
+ (OSStatus)updateKeychainItemWithSearchDictionary:(NSDictionary *)attributesToQuery
                               andUpdateDictionary:(NSDictionary *)attributesToUpdate
{
    return SecItemUpdate((__bridge CFDictionaryRef)attributesToQuery,
                         (__bridge CFDictionaryRef)attributesToUpdate);
}

//
// validateParametersAccessGroup:service:account:
//
+ (NSError *)validateParametersAccessGroup:(NSString *)accessGroup
                                   service:(NSString *)service
                                   account:(NSString *)account
{
    NSError *error = [CUTKeychain validateAccessGroup:accessGroup];
    if (error != nil)
    {
        return error;
    }
    
    error = [self validateServiceAttribute:service];
    if (error != nil)
    {
        return error;
    }
    
    if (account == nil)
    {
        NSString *errMsg =  @"account parameter is nil";
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTErrorInvalidArgument
                                message:errMsg];
    }
    
    return nil;
}

//
// validateParametersAccessGroup:service:account:data:
//
+ (NSError *)validateParametersAccessGroup:(NSString *)accessGroup
                                   service:(NSString *)service
                                   account:(NSString *)account
                                      data:(NSData *)data
{
    NSError *error = [CUTKeychain validateData:data];
    if (error != nil)
    {
        return error;
    }
    
    return [CUTKeychain validateParametersAccessGroup:accessGroup service:service account:account];
}

//
// validateParametersAccessGroup:andData:
//
+ (NSError *)validateParametersAccessGroup:(NSString *)accessGroup
                                   andData:(NSData *)data
{
    NSError *error = [CUTKeychain validateData:data];
    if (error != nil)
    {
        return error;
    }
    
    return [CUTKeychain validateAccessGroup:accessGroup];
}

//
// validateData:
//
+ (NSError *)validateData:(NSData *)data
{
    if (data == nil)
    {
        NSString *errMsg =  @"data (keychain item) parameter is nil";
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTErrorInvalidArgument
                                message:errMsg];
    }
    
    return nil;
}

//
// validateAccessGroup:
//
+ (NSError *)validateAccessGroup:(NSString *)accessGroup
{
    if ([accessGroup isEqualToString:@""])
    {
        NSString *errMsg =  @"accessGroup parameter is empty. To ignore accessgroup use nil.";
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTErrorInvalidArgument
                                message:errMsg];
    }
    
    return nil;
}


//
// validateServiceAttribute:
//
+ (NSError *)validateServiceAttribute:(NSString*)service
{
    if (service == nil)
    {
        NSString *errMsg =  @"service parameter is nil";
        CUTTrace(CUTTraceLevelError, kCUTUtilityDomain, @"%@", errMsg);
        return [NSError errorWithDomain:kCUTUtilityDomain
                                   code:CUTErrorInvalidArgument
                                message:errMsg];
    }
    return nil;
}


//
// archiveData:withKey:
// using NSKeyedArchiver to archive the data.
//
+ (NSData *)archiveData:(id)data withKey:(NSString *)key
{
    NSMutableData *archivedData = [NSMutableData new];
    NSKeyedArchiver* archiver = [[NSKeyedArchiver alloc] initForWritingWithMutableData:archivedData];
    [archiver encodeObject:data forKey:key];
    [archiver finishEncoding];
    
    return archivedData;
}

//
// unarchiveData:key:
//
+ (id)unarchiveData:(id)data key:(NSString *)key
{
    NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingWithData:data];
    id unarchiveData = [unarchiver decodeObjectForKey:key];
    [unarchiver finishDecoding];
    
    return unarchiveData;
}

//
// bundleSeedIDAccount
// returns the account value that is used to store the bundle seed ID.
// Mainly used as a test hook. In unit tests this method will be mocked.
//
+ (NSString *)bundleSeedIDAccount
{
    return @"bundleSeedID";
}

//
// reset the bundle ID. Test Hook for UTs.
//
+ (void)resetBundleId
{
#ifdef DEBUG
    bundleSeedID = nil;
#endif

}

//
// Mask the account name for release builds before tracing.
// The account name can be traced in DEBUG builds.
//
+ (NSString *)traceableStringForAccount:(NSString *)account
{
#ifdef DEBUG
    return account;
#else
    return [account stringByMaskingCharacters];
#endif
}


@end

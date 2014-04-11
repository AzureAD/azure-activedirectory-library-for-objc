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

#import "ADKeyChainHelper.h"
extern NSString* const sKeyChainlog;

@implementation ADKeyChainHelper


//Adds the shared group to the attributes dictionary. The method is not thread-safe.
-(void) adGroupToAttributes: (NSMutableDictionary*) attributes
                      group: (NSString*) group
{
    if (attributes && ![NSString isStringNilOrBlank:group])
    {
        //Apps are not signed on the simulator, so the shared group doesn't apply there.
#if !(TARGET_IPHONE_SIMULATOR)
        [attributes setObject:group forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    }
}

//Given a set of attributes, deletes the matching keychain keys:
-(void) deleteByAttributes: (NSDictionary*) attributes
                     class: (
                     group: (NSString*) group
                     error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_ON_NIL_ARGUMENT(attributes);
    
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:attributes];
    [query setObject:mClassValue forKey:mClassKey];
    [query setObject:mLibraryValue forKey:mLibraryKey];
    [self adGroupToAttributes:query group:group];
    AD_LOG_VERBOSE_F(sKeyChainlog, @"Attempting to remove items that match attributes: %@", attributes);
    
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



@end

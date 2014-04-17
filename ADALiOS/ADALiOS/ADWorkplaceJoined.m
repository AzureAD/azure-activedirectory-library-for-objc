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

#import "ADWorkplaceJoined.h"
#import "ADAuthenticationSettings.h"
#import "NSString+ADHelperMethods.h"
#import "ADErrorCodes.h"
#import "ADKeyChainHelper.h"
#import "ADALiOS.h"
#import "HTTPProtocol.h"

@implementation ADWorkplaceJoined

+(BOOL) startTLSSessionWithError: (ADAuthenticationError *__autoreleasing *) error
{
    NSString* keychainGroup = [ADAuthenticationSettings sharedInstance].clientTLSKeychainGroup;
    ADKeyChainHelper* certHelper = [[ADKeyChainHelper alloc] initWithClass:(__bridge id)kSecClassCertificate
                                                                   generic:nil
                                                               sharedGroup:keychainGroup];
    SecCertificateRef certificate = (SecCertificateRef)[certHelper getItemTypeRefWithAttributes:[NSDictionary new] error:error];
    if (!certificate)
    {
        return NO;//Quick exit, no resources to cleanup
    }
    
//    ADKeyChainHelper* identityHelper = [[ADKeyChainHelper alloc] initWithClass:(__bridge id)kSecClassIdentity
//                                                                       generic:nil
//                                                                   sharedGroup:keychainGroup];
//    SecIdentityRef identity = (SecIdentityRef)[identityHelper getItemTypeRefWithAttributes:[NSDictionary new] error:error];
    BOOL succeeded = NO;
//    if (identity)
    {
//        [HTTPProtocol setIdentity:identity];
        [HTTPProtocol setCertificate:certificate];
        if ([NSURLProtocol registerClass:[HTTPProtocol class]])
        {
            succeeded = YES;
        }
        else
        {
            ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Failed to register NSURLProtocol."];
            if (error)
            {
                *error = adError;
            }
        }
        //CFRelease(identity);
    }
    //CFRelease(certificate);
    return succeeded;
}

/* Stops the HTTPS interception. */
+(void) endTLSSession
{
    [NSURLProtocol unregisterClass:[HTTPProtocol class]];
}

//+ (OSStatus)extractIdentity:(SecIdentityRef *)outIdentity fromPKCS12Data:(NSData *) data
//{
//    OSStatus      error   = errSecSuccess;
//    NSDictionary *options = [NSDictionary new];
//    CFArrayRef    items   = CFArrayCreate( NULL, 0, 0, NULL );
//    
//    // Import the PFX/P12 using the options; the items array is the set of identities and certificates in the PFX/P12
//    error = SecPKCS12Import( (__bridge CFDataRef)data, (__bridge CFDictionaryRef)options, &items );
//    
//    if ( error == 0 )
//    {
//        // The client certificate is assumed to be the first one in the set
//        CFDictionaryRef clientIdentity = CFArrayGetValueAtIndex( items, 0);
//        const void     *tempIdentity   = CFDictionaryGetValue( clientIdentity, kSecImportItemIdentity );
//        
//        CFRetain( tempIdentity );
//        *outIdentity = (SecIdentityRef)tempIdentity;
//    }
//    else
//    {
//        DebugLog( @"Failed with error %d", (int)error );
//    }
//    
//    CFRelease( items );
//    
//    return error;
//}


@end

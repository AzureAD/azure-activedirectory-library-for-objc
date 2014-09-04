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

#import <Foundation/Foundation.h>
#import "RegistrationInformation.h"
#import "WorkPlaceJoin.h"

@interface WorkPlaceJoinUtil : NSObject

@property (nonatomic, readwrite) WorkPlaceJoin *workplaceJoin;

+ (WorkPlaceJoinUtil*) WorkPlaceJoinUtilManager;

- (NSError*)getCertificateForAccessGroup: (NSString*)sharedAccessGroup
                                identity: (SecIdentityRef*) identity
                             certificate: (SecCertificateRef*) clientCertificate;

- (RegistrationInformation*)getRegistrationInformation: (NSString*) sharedAccessGroup
                                                 error: (NSError**) error;

- (NSData *) base64DataFromString: (NSString *)string;

- (NSError*) buildNSErrorForDomain:(NSString*)domain
                         errorCode:(NSInteger) errorCode
                      errorMessage:(NSString*) message
                   underlyingError:(NSError*) underlyingError
                       shouldRetry:(BOOL) retry;

- (NSString*)getApplicationIdentifierPrefix;

@end
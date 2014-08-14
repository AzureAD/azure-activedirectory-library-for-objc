//
//  WorkPlaceJoinUtil.h
//  WorkPlaceJoinAPI
//
//  Created by Roger Toma on 3/19/14.
//  Copyright (c) 2014 Roger Toma. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RegistrationInformation.h"
#import "WorkPlaceJoin.h"

@interface WorkPlaceJoinUtil : NSObject

@property (nonatomic, readwrite) WorkPlaceJoin *workplaceJoin;

+ (WorkPlaceJoinUtil*) WorkPlaceJoinUtilManager;

- (NSData *)getPrivateKeyForAccessGroup: (NSString*)sharedAccessGroup
                   privateKeyIdentifier: (NSString*) privateKey
                                  error: (NSError**) error;

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

- (void) Log: (NSString*) logMessage;

@end
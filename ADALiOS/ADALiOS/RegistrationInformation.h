//
//  RegistrationInformation.h
//  WorkPlaceJoin
//
//  Created by Roger Toma on 3/6/14.
//  Copyright (c) 2014 Roger Toma. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RegistrationInformation : NSObject

@property (nonatomic, readonly) SecIdentityRef securityIdentity;
@property (nonatomic, readonly) SecCertificateRef certificate;
@property (nonatomic, readonly) NSString *certificateSubject;
@property (nonatomic, readonly) NSString *certificateProperties;
@property (nonatomic, readonly) NSData *certificateData;
@property (nonatomic, readonly) SecKeyRef privateKey;
@property (nonatomic, readonly) NSData *privateKeyData;
@property (nonatomic, readonly) NSString *userPrincipalName;

-(id)initWithSecurityIdentity:(SecIdentityRef)identity
            userPrincipalName:(NSString*)userPrincipalName
        certificateProperties:(NSString*)certificateProperties
                  certificate:(SecCertificateRef)certificate
           certificateSubject:(NSString*)certificateSubject
              certificateData:(NSData*)certificateData
                   privateKey:(SecKeyRef)privateKey
               privateKeyData:(NSData*)privateKeyData;

@end


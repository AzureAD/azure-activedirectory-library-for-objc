//
//  WPJRegistrationInformation.m
//  Company Portal
//
//  Created by Roger Toma on 03/15/14.
//  Copyright (c) 2013 Contoso Ltd. All rights reserved.
//

#import "RegistrationInformation.h"

@implementation RegistrationInformation

@synthesize securityIdentity = _securityIdentity;
@synthesize userPrincipalName = _userPrincipalName;
@synthesize certificate = _certificate;
@synthesize certificateSubject = _certificateSubject;
@synthesize certificateData = _certificateData;
@synthesize certificateProperties = _certificateProperties;
@synthesize privateKey = _privateKey;
@synthesize privateKeyData = _privateKeyData;

-(id)initWithSecurityIdentity:(SecIdentityRef)identity
            userPrincipalName:(NSString*)userPrincipalName
        certificateProperties:(NSString*)certificateProperties
                  certificate:(SecCertificateRef)certificate
           certificateSubject:(NSString*)certificateSubject
              certificateData:(NSData*)certificateData
                   privateKey:(SecKeyRef)privateKey
               privateKeyData:(NSData *)privateKeyData

{
    self = [super init];
    if(self)
    {
        _securityIdentity = identity;
        _userPrincipalName = userPrincipalName;
        _certificate = certificate;
        _certificateSubject = certificateSubject;
        _certificateData = certificateData;
        _privateKey = privateKey;
        _privateKeyData = privateKeyData;
        _certificateProperties = certificateProperties;
        
        return self;
    }
    return nil;
}

@end

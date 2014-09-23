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

#import "ADRegistrationInformation.h"

@implementation ADRegistrationInformation

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

- (BOOL) isWorkPlaceJoined{
    return _certificate != nil;
}


-(void) releaseData{
    if(self){
        if(_securityIdentity){
            CFRelease(_securityIdentity);
            _securityIdentity = nil;
        }
        
        if(_certificate){
            CFRelease(_certificate);
            _certificate = nil;
        }
        
        if(_privateKey){
            CFRelease(_privateKey);
            _privateKey = nil;
        }
        
        if(_certificateSubject){
            CFRelease((__bridge CFTypeRef)(_certificateSubject));
            _certificateSubject = nil;
        }
        
        if(_certificateData){
            _certificateData = nil;
        }
        
        if(_userPrincipalName){
            CFRelease((__bridge CFTypeRef)(_userPrincipalName));
            _userPrincipalName = nil;
        }
        
        if(_certificateProperties){
            CFRelease((__bridge CFTypeRef)(_certificateProperties));
            _certificateProperties = nil;
        }
    }
}

@end

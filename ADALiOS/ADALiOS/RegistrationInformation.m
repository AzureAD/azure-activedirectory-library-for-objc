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

#import "RegistrationInformation.h"

@implementation RegistrationInformation

@synthesize certificate      = _certificate;
@synthesize identity  = _identity;
@synthesize privateKey   = _privateKey;
@synthesize userPrincipalName = _userPrincipalName;
@synthesize certificateSubject = _certificateSubject;
@synthesize certificateData = _certificateData;
@synthesize certificateIssuer = _certificateIssuer;
@synthesize privateKeyData = _privateKeyData;

-(id)initWithSecurityIdentity:(SecIdentityRef)identity
            userPrincipalName:(NSString*)userPrincipalName
        certificateIssuer:(NSString*)certificateIssuer
                  certificate:(SecCertificateRef)certificate
           certificateSubject:(NSString*)certificateSubject
              certificateData:(NSData*)certificateData
                   privateKey:(SecKeyRef)privateKey
               privateKeyData:(NSData *)privateKeyData

{
    self = [super init];
    if(self)
    {
        _identity = identity;
        CFRetain(_identity);
        _userPrincipalName = SAFE_ARC_RETAIN(userPrincipalName);
        _certificate = certificate;
        CFRetain(_certificate);
        _certificateSubject = SAFE_ARC_RETAIN(certificateSubject);
        _certificateData = SAFE_ARC_RETAIN(certificateData);
        _privateKey = privateKey;
        CFRetain(_privateKey);
        _privateKeyData = SAFE_ARC_RETAIN(privateKeyData);
        _certificateIssuer = SAFE_ARC_RETAIN(certificateIssuer);
        
        return self;
    }
    return nil;
}

- (BOOL) isWorkPlaceJoined{
    return _certificate != nil;
}

- (void)dealloc
{
    AD_LOG_VERBOSE(@"RegistrationInformation", @"dealloc");
    [self releaseData];
    
    SAFE_ARC_SUPER_DEALLOC();
}

-(void) releaseData{
    if(self){
        if(_identity){
            CFRelease(_identity);
            _identity = nil;
        }
        
        if(_certificate){
            CFRelease(_certificate);
            _certificate = nil;
        }
        
        if(_privateKey){
            CFRelease(_privateKey);
            _privateKey = nil;
        }
        
        if(_privateKeyData){
            SAFE_ARC_RELEASE(_privateKeyData);
            _privateKeyData = nil;
        }
        
        if(_certificateSubject){
            SAFE_ARC_RELEASE(_certificateSubject);
            _certificateSubject = nil;
        }
        
        if(_certificateData){
            SAFE_ARC_RELEASE(_certificateData);
            _certificateData = nil;
        }
        
        if(_userPrincipalName){
            SAFE_ARC_RELEASE(_userPrincipalName);
            _userPrincipalName = nil;
        }
        
        if(_certificateIssuer){
            SAFE_ARC_RELEASE(_certificateIssuer);
            _certificateIssuer = nil;
        }
        
    }
}

@end

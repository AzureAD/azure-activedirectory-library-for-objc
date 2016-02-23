// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADRegistrationInformation.h"

@implementation ADRegistrationInformation

@synthesize securityIdentity = _securityIdentity;
@synthesize userPrincipalName = _userPrincipalName;
@synthesize certificate = _certificate;
@synthesize certificateSubject = _certificateSubject;
@synthesize certificateData = _certificateData;
@synthesize certificateIssuer = _certificateIssuer;
@synthesize privateKey = _privateKey;
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
        _securityIdentity = identity;
        _userPrincipalName = userPrincipalName;
        _certificate = certificate;
        _certificateSubject = certificateSubject;
        _certificateData = certificateData;
        _privateKey = privateKey;
        _privateKeyData = privateKeyData;
        _certificateIssuer = certificateIssuer;
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
            _certificateSubject = nil;
        }
        
        if(_certificateData){
            _certificateData = nil;
        }
        
        if(_userPrincipalName){
            _userPrincipalName = nil;
        }
        
        if(_certificateIssuer){
            _certificateIssuer = nil;
        }
    }
}

@end

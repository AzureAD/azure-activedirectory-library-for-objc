//
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

#import "ADOpenSSLHelper.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

@implementation ADOpenSSLHelper : NSObject

+ (NSMutableSet*) getCertificateIssuer:(NSData*)certificateData
{
    X509 *certificateX509;
    const unsigned char *certificateDataBytes = (const unsigned char *)[certificateData bytes];
    certificateX509 =  d2i_X509(NULL, &certificateDataBytes, [certificateData length]);
    NSMutableSet* issuer = [NSMutableSet new];
    if (certificateX509 != NULL) {
        X509_NAME *issuerX509Name = X509_get_issuer_name(certificateX509);
        if (issuerX509Name != NULL) {
            [issuer addObjectsFromArray:[self getX509EntryData:issuerX509Name nid:NID_domainComponent shortName:@"DC"]];
            [issuer addObjectsFromArray:[self getX509EntryData:issuerX509Name nid:NID_commonName shortName:@"CN"]];
            [issuer addObjectsFromArray:[self getX509EntryData:issuerX509Name nid:NID_organizationalUnitName shortName:@"OU"]];
        }
        
        X509_free(certificateX509);
    }
    return issuer;
}

+ (NSArray*) getX509EntryData:(X509_NAME*) issuerX509Name
                               nid:(int) nid
                    shortName:(NSString*) shortName{
    int loc = -1;
    X509_NAME_ENTRY *e;
    NSMutableArray* values =  [NSMutableArray new];
    for (;;)
    {
        loc = X509_NAME_get_index_by_NID(issuerX509Name, nid, loc);
        if (loc == -1){
            break;
        }
        
        e = X509_NAME_get_entry(issuerX509Name, loc);
        if (e) {
            ASN1_STRING *issuerNameASN1 = X509_NAME_ENTRY_get_data(e);
            
            if (issuerNameASN1 != NULL) {
                unsigned char *issuerName = ASN1_STRING_data(issuerNameASN1);
                [values addObject:[NSString stringWithFormat:@"%@=%@", shortName ,[NSString stringWithUTF8String:(char *)issuerName]]];
            }
        }
    }
    return values;
}

@end

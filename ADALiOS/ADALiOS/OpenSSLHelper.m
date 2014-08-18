//
//  OpenSSLHelper.m
//  ADALiOS
//
//  Created by Kanishk Panwar on 8/17/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import "OpenSSLHelper.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

@implementation OpenSSLHelper : NSObject

+ (NSString*) getCertificateIssuer:(NSData*)certificateData
{
    X509 *certificateX509;
    
    
    const unsigned char *certificateDataBytes = (const unsigned char *)[certificateData bytes];
    certificateX509 =  d2i_X509(NULL, &certificateDataBytes, [certificateData length]);
    NSString *issuer = nil;
    if (certificateX509 != NULL) {
        X509_NAME *issuerX509Name = X509_get_issuer_name(certificateX509);
        if (issuerX509Name != NULL) {
            int nid = OBJ_txt2nid("organizationalUnitName"); // organization
            int index = X509_NAME_get_index_by_NID(issuerX509Name, nid, -1);
            
            X509_NAME_ENTRY *issuerNameEntry = X509_NAME_get_entry(issuerX509Name, index);
            
            if (issuerNameEntry) {
                ASN1_STRING *issuerNameASN1 = X509_NAME_ENTRY_get_data(issuerNameEntry);
                
                if (issuerNameASN1 != NULL) {
                    unsigned char *issuerName = ASN1_STRING_data(issuerNameASN1);
                    issuer = [NSString stringWithUTF8String:(char *)issuerName];
                }
            }
        }
        
        X509_free(certificateX509);
    }
    
    return issuer;
}

@end

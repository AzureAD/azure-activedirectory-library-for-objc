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

+ (NSMutableSet*) getCertificateIssuer:(NSData*)certificateData
{
    X509 *certificateX509;
    const unsigned char *certificateDataBytes = (const unsigned char *)[certificateData bytes];
    certificateX509 =  d2i_X509(NULL, &certificateDataBytes, [certificateData length]);
    NSMutableSet* issuer = [NSMutableSet new];
    if (certificateX509 != NULL) {
//        ASN1_INTEGER *serial = X509_get_serialNumber(certificateX509);
//        BIGNUM *bnser = ASN1_INTEGER_to_BN(serial, NULL);
//        int n = BN_num_bytes(bnser);
//        unsigned char outbuf[n];
//        int bin = BN_bn2bin(bnser, outbuf);
//        char *hexBuf = (char*) outbuf;
//        NSMutableString *str = [[NSMutableString alloc] init];
//        for (int i=0; i<n; i++) {
//            NSString *temp = [NSString stringWithFormat:@"%.6x", hexBuf[i]];
//            [str appendString:[NSString stringWithFormat:@"%@ ", temp]];
//        }
        
        
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
    int loc;
    X509_NAME_ENTRY *e;
    loc = -1;
    NSMutableArray* values =  [NSMutableArray new];
    for (;;)
    {
        loc = X509_NAME_get_index_by_NID(issuerX509Name, nid, loc);
        if (loc == -1)
            break;
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

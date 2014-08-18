//
//  NSData+ADHelperMethods.m
//  ADALiOS
//
//  Created by Kanishk Panwar on 8/13/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import "NSData+ADHelperMethods.h"
#import <Foundation/Foundation.h>

@implementation NSData (ADHelperMethods)

typedef unsigned char byte;

static char base64UrlEncodeTable[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

#define NA (255)

static byte rgbDecodeTable[128] = {                         // character code
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,  // 0-15
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,  // 16-31
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 62, NA, NA,  // 32-47
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, NA, NA, NA,  0, NA, NA,  // 48-63
    NA,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  // 64-79
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, NA, NA, NA, NA, 63,  // 80-95
    NA, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  // 96-111
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, NA, NA, NA, NA, NA,  // 112-127
};

static inline void Encode3bytesTo4bytes(char* output, int b0, int b1, int b2)
{
    output[0] = base64UrlEncodeTable[b0 >> 2];                                  // 6 MSB from byte 0
    output[1] = base64UrlEncodeTable[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)];  // 2 LSB from byte 0 and 4 MSB from byte 1
    output[2] = base64UrlEncodeTable[((b1 << 2) & 0x3c) | ((b2 >> 6) & 0x03)];  // 4 LSB from byte 1 and 2 MSB from byte 2
    output[3] = base64UrlEncodeTable[b2 & 0x3f];
}

- (NSString *) adBase64EncodeData
{
    
    const byte *pbBytes = [self bytes];
    int         cbBytes = (int)[self length];
    
    // Calculate encoded string size including padding. This may be more than is actually
    // required since we will not pad and instead will terminate with null. The computation
    // is the number of byte triples times 4 radix64 characters plus 1 for null termination.
    int   encodedSize = 1 + ( cbBytes + 2 ) / 3 * 4;
    char *pbEncoded = (char *)calloc( encodedSize, sizeof(char) );
    
    // Encode data byte triplets into four-byte clusters.
    int   iBytes;      // raw byte index
    int   iEncoded;    // encoded byte index
    byte  b0, b1, b2;  // individual bytes for triplet
    
    iBytes = iEncoded = 0;
    
    int end3 = (cbBytes/3)*3;
    //Fast loop, no bounderies check:
    for ( ; iBytes < end3; )
    {
        b0 = pbBytes[iBytes++];
        b1 = pbBytes[iBytes++];
        b2 = pbBytes[iBytes++];
        
        Encode3bytesTo4bytes(pbEncoded + iEncoded, b0, b1, b2);
        iEncoded += 4;
    }
    
    //Slower loop should execute no more than 3 times:
    while ( iBytes < cbBytes )
    {
        b0 = pbBytes[iBytes++];
        b1 = (iBytes < cbBytes) ? pbBytes[iBytes++] : 0;                                        // Add extra zero byte if needed
        b2 = (iBytes < cbBytes) ? pbBytes[iBytes++] : 0;                                        // Add extra zero byte if needed
        
        Encode3bytesTo4bytes(pbEncoded + iEncoded, b0, b1, b2);
        iEncoded += 4;
    }
    
    // Where we would have padded it, we instead truncate the string
    switch ( cbBytes % 3 )
    {
        case 0:
            // No left overs, nothing to pad
            break;
            
        case 1:
            // One left over, normally pad 2
            pbEncoded[iEncoded - 2] = '\0';
            // fall through
            
        case 2:
            pbEncoded[iEncoded - 1] = '\0';
            break;
    }
    
    // Null terminate, convert to NSString and free the buffer
    pbEncoded[iEncoded++] = '\0';
    
    NSString *result = [NSString stringWithCString:pbEncoded encoding:NSASCIIStringEncoding];
    
    free(pbEncoded);
    
    return result;
}


@end

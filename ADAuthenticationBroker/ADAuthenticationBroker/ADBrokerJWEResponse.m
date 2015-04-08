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

#import "ADBrokerJWEResponse.h"
#import "NSString+ADBrokerHelperMethods.h"
#import "ADBrokerBase64Additions.h"

@implementation ADBrokerJWEResponse

- (id) init
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id) initWithRawJWE:(NSString*) rawJWE
{
    self = [super init];
    if(self)
    {
        NSArray* jwePieces = [rawJWE componentsSeparatedByString: @"."];
        if ([jwePieces count] < 4) {
            return nil;
        }
        
        NSString* header = [[jwePieces objectAtIndex:0] adBase64UrlDecode];
        NSError   *jsonError  = nil;
        id         jsonObject = [NSJSONSerialization JSONObjectWithData:[header dataUsingEncoding:0]
                                                                options:0
                                                                  error:&jsonError];
        
        if ( nil != jsonObject && [jsonObject isKindOfClass:[NSDictionary class]] )
        {
            _headerAlgorithm = [(NSDictionary*)jsonObject objectForKey:@"alg"];
        }
        else
        {
            return nil;
        }
        
        NSString* encryptedKey = [jwePieces objectAtIndex:1];
        encryptedKey = [encryptedKey stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
        encryptedKey = [encryptedKey stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
        
        NSString* base64PadCharacter = @"=";
        
        switch (encryptedKey.length % 4) // Pad
        {
            case 0:
                break; // No pad chars in this case
            case 2:
                encryptedKey = [NSString stringWithFormat:@"%@%@%@", encryptedKey, base64PadCharacter, base64PadCharacter];
                break; // Two pad chars
            case 3:
                encryptedKey = [NSString stringWithFormat:@"%@%@", encryptedKey, base64PadCharacter];
                break; // One pad char
        }
        
        _encryptedKey = [NSData dataWithBase64String:encryptedKey];
    }
    return self;
}

@end

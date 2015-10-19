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

#import "NSURL+ADExtensions.h"
#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"

NSString* fragmentSeparator = @"#";
NSString* queryStringSeparator = @"?";

@implementation NSURL ( ADAL )

- (NSString *)adAuthority
{
    NSInteger port = self.port.integerValue;
    
    if ( port == 0 )
    {
        if ( [self.scheme isEqualToString:@"http"] )
        {
            port = 80;
        }
        else if ( [self.scheme isEqualToString:@"https"] )
        {
            port = 443;
        }
    }
    
    return [NSString stringWithFormat:@"%@:%ld", self.host, (long)port];
}

@end

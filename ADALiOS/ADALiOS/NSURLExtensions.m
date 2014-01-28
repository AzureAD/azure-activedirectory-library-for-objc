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

#import "NSURLExtensions.h"
#import "NSDictionaryExtensions.h"
#import "NSString+ADHelperMethods.h"

NSString* const fragmentSeparator = @"#";
NSString* const queryStringSeparator = @"?";

@implementation NSURL ( IPAL )

- (NSString *)authority
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

//Used for getting the parameters from either the fragment or the query
//string. This internal helper method attempts to extract the parameters
//for the substring of the URL succeeding the separator. Also, if the
//separator is present more than once, the method returns null.
//Unlike standard NSURL implementation, the method handles well URNs.
-(NSDictionary*) getParametersAfter: (NSString*) separator
{
    NSArray* parts = [[self absoluteString] componentsSeparatedByString:separator];
    if (parts.count != 2)
    {
        return nil;
    }
    NSString* last = [parts lastObject];
    if ([NSString isStringNilOrBlank:last])
    {
        return nil;
    }
    return [NSDictionary URLFormDecode:last];
}

// Decodes parameters contained in a URL fragment
- (NSDictionary *)fragmentParameters
{
    return [self getParametersAfter:fragmentSeparator];
}

// Decodes parameters contains in a URL query
- (NSDictionary *)queryParameters
{
    return [self getParametersAfter:queryStringSeparator];
}

@end

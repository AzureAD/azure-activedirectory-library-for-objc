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

#import "NSURL+ADExtensions.h"
#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"

const unichar fragmentSeparator = '#';
const unichar queryStringSeparator = '?';

@implementation NSURL (ADAL)

// Decodes parameters contained in a URL fragment
- (NSDictionary *)adFragmentParameters
{
    return [NSDictionary adURLFormDecode:self.fragment];
}

// Decodes parameters contains in a URL query
- (NSDictionary *)adQueryParameters
{
    NSURLComponents* components = [NSURLComponents componentsWithURL:self resolvingAgainstBaseURL:YES];
    
    return [NSDictionary adURLFormDecode:[components percentEncodedQuery]];
}

- (NSURL *)adURLWithQueryParameters:(NSDictionary *)queryParameters
{
    if (![queryParameters count])
    {
        return self;
    }

    // Pull apart the request URL
    NSURLComponents *components = [[NSURLComponents alloc] initWithURL:self resolvingAgainstBaseURL:NO];

    if (!components)
    {
        return nil;
    }

    NSString *query = [components percentEncodedQuery];

    for (NSString *key in [queryParameters allKeys])
    {
        if (query && [query containsString:key])
        {
            // Don't bother adding it if it's already there
            continue;
        }

        NSString *queryEntry = [NSString stringWithFormat:@"%@=%@", key.adUrlFormEncode, [queryParameters[key] adUrlFormEncode]];

        if (query)
        {
            query = [query stringByAppendingFormat:@"&%@", queryEntry];
        }
        else
        {
            query = queryEntry;
        }
    }

    if (query)
    {
        [components setPercentEncodedQuery:query];
    }

    return [components URL];
}

- (BOOL)isEquivalentAuthority:(NSURL *)aURL
{
    
    // Check if equal
    if ([self isEqual:aURL])
    {
        return YES;
    }
    
    // Check scheme and host
    if (!self.scheme ||
        !aURL.scheme ||
        [self.scheme caseInsensitiveCompare:aURL.scheme] != NSOrderedSame)
    {
        return NO;
    }
    
    if (!self.host ||
        !aURL.host ||
        [self.host caseInsensitiveCompare:aURL.host] != NSOrderedSame)
    {
        return NO;
    }
    
    // Check port
    if (self.port || aURL.port)
    {
        if (![self.port isEqual:aURL.port])
        {
            return NO;
        }
    }
    
    return YES;
}

- (NSString *)adHostWithPortIfNecessary
{
    NSNumber *port = self.port;
    
    // This assumes we're using https, which is mandatory for all AAD communications.
    if (port == nil || port.intValue == 443)
    {
        return self.host.lowercaseString;
    }
    return [NSString stringWithFormat:@"%@:%d", self.host.lowercaseString, port.intValue];
}

@end

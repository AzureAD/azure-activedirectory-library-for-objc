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

//Used for getting the parameters from either the fragment or the query
//string. This internal helper method attempts to extract the parameters
//for the substring of the URL succeeding the separator. Also, if the
//separator is present more than once, the method returns null.
//Unlike standard NSURL implementation, the method handles well URNs.
-(NSDictionary*) getParametersAfter: (unichar) startSeparator
                              until: (unichar) endSeparator
{
    NSArray* parts = [[self absoluteString] componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithRange:(NSRange){startSeparator, 1}]];
    if (parts.count != 2)
    {
        return nil;
    }
    NSString* last = [parts lastObject];
    if (endSeparator)
    {
        long index = [last adFindCharacter:endSeparator start:0];
        
        if (index == NSNotFound)
        {
            return nil;
        }
        last = [last substringWithRange:(NSRange){0, index}];
    }
    if ([NSString adIsStringNilOrBlank:last])
    {
        return nil;
    }
    return [NSDictionary adURLFormDecode:last];
}

// Decodes parameters contained in a URL fragment
- (NSDictionary *)adFragmentParameters
{
    return [NSDictionary adURLFormDecode:self.fragment];
}

// Decodes parameters contains in a URL query
- (NSDictionary *)adQueryParameters
{
    return [self getParametersAfter:queryStringSeparator until:fragmentSeparator];
}

@end

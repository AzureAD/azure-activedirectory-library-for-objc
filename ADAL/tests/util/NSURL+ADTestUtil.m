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

#import <objc/runtime.h>

#import "NSURL+ADTestUtil.h"
#import "NSURL+ADExtensions.h"
#import "NSDictionary+ADExtensions.h"
#import "NSDictionary+ADTestUtil.h"

@implementation NSURL (ADTestUtil)

- (NSDictionary *)cachedQueryParameterDictionary
{
    if (!self.query)
    {
        return nil;
    }
    
    static const void *key = "adtestutil_qp_dict";
    NSDictionary *myQPs = objc_getAssociatedObject(self, key);
    if (myQPs)
    {
        return myQPs;
    }
    
    myQPs = [self adQueryParameters];
    objc_setAssociatedObject(self, key, myQPs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return myQPs;
}

- (BOOL)matchesURL:(NSURL *)url
{
    // Start with making sure the base URLs match up
    if ([url.scheme caseInsensitiveCompare:self.scheme] != NSOrderedSame)
    {
        return NO;
    }
    
    if ([[url adHostWithPortIfNecessary] caseInsensitiveCompare:[self adHostWithPortIfNecessary]] != NSOrderedSame)
    {
        return NO;
    }
    
    // Then the relative portions
    if ([url.relativePath caseInsensitiveCompare:self.relativePath] != NSOrderedSame)
    {
        return NO;
    }
    
    // And lastly, the tricky part. Query Params can come in any order so we need to process them
    // a bit instead of just a string compare
    NSDictionary *myQPs = [self cachedQueryParameterDictionary];
    NSDictionary *theirQPs = [url cachedQueryParameterDictionary];
    if (theirQPs)
    {
        return [myQPs compareAndPrintDiff:theirQPs dictionaryDescription:@"URL QPs"];
    }
    else if (myQPs)
    {
        return NO;
    }
    
    return YES;
}

@end

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

#import "ADALFrameworkUtils.h"
#import "ADAL_Internal.h"

double ADALFrameworkNumber = ADAL_VERSION_NUMBER;

const unsigned char ADALFrameworkVersionString[] = ADAL_VERSION_STRING;

@implementation ADALFrameworkUtils

static NSString *_resourcePath = nil;

+ (NSString *)resourcePath
{
    return _resourcePath;
}

+ (void)setResourcePath:(NSString *)resourcePath
{
    if (_resourcePath == resourcePath)
    {
        return;
    }
    _resourcePath = [resourcePath copy];
}

// Retrive the bundle containing the resources for the library. May return nil, if the bundle
// cannot be loaded.
+ (NSBundle *)frameworkBundle
{
    static NSBundle       *bundle     = nil;
    static dispatch_once_t predicate;
    dispatch_once( &predicate, ^{
        
        NSString* mainBundlePath      = [[NSBundle mainBundle] resourcePath];
        AD_LOG_VERBOSE(nil, @"Resources Loading - Attempting to load resources");
        AD_LOG_VERBOSE_PII(nil, @"Resources Loading - Attempting to load resources from: %@", mainBundlePath);
        NSString* frameworkBundlePath = nil;
        
        if ( _resourcePath != nil )
        {
            frameworkBundlePath = [[mainBundlePath stringByAppendingPathComponent:_resourcePath] stringByAppendingPathComponent:@"ADALiOS.bundle"];
        }
        else
        {
            frameworkBundlePath = [mainBundlePath stringByAppendingPathComponent:@"ADALiOS.bundle"];
        }
        
        bundle = [NSBundle bundleWithPath:frameworkBundlePath];
        if (bundle)
        {
            return;
        }
        
        bundle = [NSBundle bundleForClass:[ADALFrameworkUtils class]];
        if (!bundle)
        {
            AD_LOG_INFO(nil, @"Resource Loading - Failed to load framework bundle. Application main bundle will be attempted.");
        }
    });
    
    return bundle;
}


@end

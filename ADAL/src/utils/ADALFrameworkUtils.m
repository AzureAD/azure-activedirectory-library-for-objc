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

#import "ADALFrameworkUtils.h"
#import "ADAL_Internal.h"

@implementation ADALFrameworkUtils

static NSString *_resourcePath = nil;

+ (NSString *)resourcePath
{
    return _resourcePath;
}

+ (void)setResourcePath:(NSString *)resourcePath
{
    _resourcePath = resourcePath;
}

// Retrive the bundle containing the resources for the library. May return nil, if the bundle
// cannot be loaded.
+ (NSBundle *)frameworkBundle
{
    static NSBundle       *bundle     = nil;
    static dispatch_once_t predicate;
    dispatch_once( &predicate, ^{
        
        NSString* mainBundlePath      = [[NSBundle mainBundle] resourcePath];
        AD_LOG_VERBOSE_F(@"Resources Loading", nil, @"Attempting to load resources from: %@", mainBundlePath);
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
            AD_LOG_INFO_F(@"Resource Loading", nil, @"Failed to load framework bundle. Application main bundle will be attempted.");
        }
    });
    
    return bundle;
}


@end
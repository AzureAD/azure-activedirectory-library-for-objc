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

#import "ADCustomHeaderHandler.h"

@implementation ADCustomHeaderHandler

static NSDictionary* customHeaders;
static NSMutableDictionary* customHeadersForSingleUse;

+ (void)initialize
{
    if (self == [ADCustomHeaderHandler class]) {
        customHeaders = @{
                         @"x-ms-PkeyAuth":@"1.0",
                         };
        customHeadersForSingleUse = [NSMutableDictionary new];
    }
}

+(void) addCustomHeaderValue:(NSString*)value forHeaderKey:(NSString*)key forSingleUse:(BOOL)singleUse
{
    if(singleUse)
    {
        [customHeadersForSingleUse setObject:value forKey:key];
    }
    else
    {
        [customHeaders setValue:value forKey:key];
    }
}

+(void) applyCustomHeadersTo:(NSMutableURLRequest*) request
{
    for(NSString* key in customHeaders) {
        id value = [customHeaders objectForKey:key];
        [request setValue:value forHTTPHeaderField:key];
    }
    
    for(NSString* key in customHeadersForSingleUse) {
        id value = [customHeadersForSingleUse objectForKey:key];
        [request setValue:value forHTTPHeaderField:key];
        [customHeadersForSingleUse removeObjectForKey:key];
    }
}

@end

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

static NSMutableDictionary* s_customHeaders = nil;
static NSMutableDictionary* s_customHeadersForSingleUse = nil;

+ (void)initialize
{
    if (self == [ADCustomHeaderHandler class])
    {
        s_customHeaders =
            [NSMutableDictionary dictionaryWithDictionary: @{@"x-ms-PkeyAuth":@"1.0"}];
        SAFE_ARC_RETAIN(s_customHeaders);
        s_customHeadersForSingleUse = [NSMutableDictionary new];
    }
}

+ (void)addCustomHeaderValue:(NSString*)value
                forHeaderKey:(NSString*)key
                forSingleUse:(BOOL)singleUse
{
    if(singleUse)
    {
        [s_customHeadersForSingleUse setObject:value forKey:key];
    }
    else
    {
        [s_customHeaders setObject:value forKey:key];
    }
}

+ (void)applyCustomHeadersTo:(NSMutableURLRequest*) request
{
    for(NSString* key in s_customHeaders)
    {
        id value = [s_customHeaders objectForKey:key];
        [request setValue:value forHTTPHeaderField:key];
    }
    
    for(NSString* key in s_customHeadersForSingleUse)
    {
        id value = [s_customHeadersForSingleUse objectForKey:key];
        [request setValue:value forHTTPHeaderField:key];
        [s_customHeadersForSingleUse removeObjectForKey:key];
    }
}

@end

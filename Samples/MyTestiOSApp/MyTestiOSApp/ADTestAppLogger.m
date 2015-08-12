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


#import "ADTestAppLogger.h"

static void (^s_logCallback)(NSString* message, TALogType type) = nil;

@implementation ADTestAppLogger


+ (void)logMessage:(NSString*)message
              type:(TALogType)type
{
    if (!s_logCallback)
    {
        NSLog(@"%@", message);
    }
    else
    {
        s_logCallback(message, type);
    }
}

+ (void)registerLogCallback:(void (^)(NSString* message, TALogType type))callback
{
    s_logCallback = callback;
}


@end

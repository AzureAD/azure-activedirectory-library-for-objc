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


#import "ADLogger+Broker.h"
#import "NSString+ADHelperMethods.h"
#import "ADOAuth2Constants.h"
#import "ADBrokerConstants.h"

#define BROKER_VER_HIGH   1
#define BROKER_VER_LOW    0
#define BROKER_VER_PATCH  0

@implementation ADLogger (Broker)

NSString* clientAdalVersion = @"0.0.0";

+(void) resetAdalVersion
{
    clientAdalVersion = @"0.0.0";
}

+(void) setAdalVersion:(NSString*) adalVersion
{
    clientAdalVersion = adalVersion;
}

+(NSDictionary*) adalId
{
    UIDevice* device = [UIDevice currentDevice];
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                   @{
                                     ADAL_ID_PLATFORM:@"iOS",
                                     ADAL_ID_VERSION:clientAdalVersion,
                                     ADAL_ID_OS_VER:device.systemVersion,
                                     ADAL_ID_DEVICE_MODEL:device.model,//Prints out only "iPhone" or "iPad".
                                     ADAL_ID_BROKER_VER:[NSString stringWithFormat:@"%d.%d.%d", BROKER_VER_HIGH, BROKER_VER_LOW, BROKER_VER_PATCH],
                                     }];
    NSString* CPUVer = [self getCPUInfo];
    if (![NSString adIsStringNilOrBlank:CPUVer])
    {
        [result setObject:CPUVer forKey:ADAL_ID_CPU];
    }
    return result;
}

@end

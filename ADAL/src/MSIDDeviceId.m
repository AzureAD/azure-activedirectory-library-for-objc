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

#import "MSIDDeviceId.h"
#import "ADOAuth2Constants.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>

static NSMutableDictionary *s_adalId = nil;

@implementation MSIDDeviceId

//Extracts the CPU information according to the constants defined in
//machine.h file. The method prints minimal information - only if 32 or
//64 bit CPU architecture is being used.
+ (NSString*)getCPUInfo
{
    size_t structSize;
    cpu_type_t cpuType;
    structSize = sizeof(cpuType);
    
    //Extract the CPU type. E.g. x86. See machine.h for details
    //See sysctl.h for details.
    int result = sysctlbyname("hw.cputype", &cpuType, &structSize, NULL, 0);
    if (result)
    {
        AD_LOG_WARN(nil, @"Cannot extract cpu type. Error: %d", result);
        
        return nil;
    }
    
    return (CPU_ARCH_ABI64 & cpuType) ? @"64" : @"32";
}

/*! Returns diagnostic trace data to be sent to the Auzure Active Directory servers. */
+ (NSDictionary *)deviceId
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#if TARGET_OS_IPHONE
        //iOS:
        UIDevice* device = [UIDevice currentDevice];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"iOS",
                                         ADAL_ID_VERSION:ADAL_VERSION_NSSTRING,
                                         ADAL_ID_OS_VER:device.systemVersion,
                                         ADAL_ID_DEVICE_MODEL:device.model,//Prints out only "iPhone" or "iPad".
                                         }];
#else
        NSOperatingSystemVersion osVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"OSX",
                                         ADAL_ID_VERSION:[NSString stringWithFormat:@"%d.%d.%d", ADAL_VER_HIGH, ADAL_VER_LOW, ADAL_VER_PATCH],
                                         ADAL_ID_OS_VER:[NSString stringWithFormat:@"%ld.%ld.%ld", (long)osVersion.majorVersion, (long)osVersion.minorVersion, (long)osVersion.patchVersion],
                                         }];
#endif
        NSString* CPUVer = [self getCPUInfo];
        if (![NSString msidIsStringNilOrBlank:CPUVer])
        {
            [result setObject:CPUVer forKey:ADAL_ID_CPU];
        }
        
        s_adalId = result;
    });
    
    return s_adalId;
}

+ (void)setIdValue:(NSString*)value
            forKey:(NSString*)key
{
    [(NSMutableDictionary *)[self deviceId] setObject:value forKey:key];
}

@end

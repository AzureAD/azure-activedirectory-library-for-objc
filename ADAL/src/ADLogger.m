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

#import "ADAL_Internal.h"
#import "ADOAuth2Constants.h"
#import "ADLogger+Internal.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#include <CommonCrypto/CommonDigest.h>
#if TARGET_OS_WATCH
#include <WatchKit/WatchKit.h>
#endif

@protocol LoggerContext <NSObject>

- (NSString *)component;

@end

static ADAL_LOG_LEVEL s_LogLevel = ADAL_LOG_LEVEL_ERROR;
static LogCallback s_LogCallback = nil;
static BOOL s_NSLogging = YES;
static NSString* s_OSString = @"UnkOS";

static NSMutableDictionary* s_adalId = nil;

static dispatch_once_t s_logOnce;

@implementation ADLogger

+ (void)initialize
{
#if TARGET_OS_IPHONE
    UIDevice* device = [UIDevice currentDevice];

#if TARGET_OS_SIMULATOR
    s_OSString = [NSString stringWithFormat:@"iOS Sim %@", device.systemVersion];
#else
    s_OSString = [NSString stringWithFormat:@"iOS %@", device.systemVersion];
#endif
#elif TARGET_OS_WATCH
#error watchOS is not supported
#elif TARGET_OS_TV
#error tvOS is not supported
#else
    NSOperatingSystemVersion osVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
    s_OSString = [NSString stringWithFormat:@"Mac %ld.%ld.%ld", (long)osVersion.majorVersion, (long)osVersion.minorVersion, (long)osVersion.patchVersion];
    SAFE_ARC_RETAIN(s_OSString);
#endif
}

+ (void)setLevel:(ADAL_LOG_LEVEL)logLevel
{
    s_LogLevel = logLevel;
}

+ (ADAL_LOG_LEVEL)getLevel
{
    return s_LogLevel;
}

+ (void)setLogCallBack:(LogCallback)callback
{
    @synchronized(self)//Avoid changing to null while attempting to call it.
    {
        s_LogCallback = [callback copy];
    }
}


+ (void)setNSLogging:(BOOL)nslogging
{
    s_NSLogging = nslogging;
}

+ (BOOL)getNSLogging
{
    return s_NSLogging;
}

@end

@implementation ADLogger (Internal)

+ (LogCallback)getLogCallBack
{
    @synchronized(self)
    {
        return s_LogCallback;
    }
}

+ (NSString*)stringForLevel:(ADAL_LOG_LEVEL)level
{
    switch (level)
    {
        case ADAL_LOG_LEVEL_ERROR: return @"ERROR";
        case ADAL_LOG_LEVEL_WARN: return @"WARNING";
        case ADAL_LOG_LEVEL_INFO: return @"INFO";
        case ADAL_LOG_LEVEL_VERBOSE: return @"VERBOSE";
        case ADAL_LOG_LEVEL_NO_LOG: return @"NONE";
    }
}

+ (void)log:(ADAL_LOG_LEVEL)logLevel
    context:(id)context
    message:(NSString*)message
  errorCode:(NSInteger)errorCode
       info:(NSString*)info
correlationId:(NSUUID*)correlationId
   userInfo:(NSDictionary *)userInfo
{
    static NSDateFormatter* s_dateFormatter = nil;
    static dispatch_once_t s_dateOnce;
    
    dispatch_once(&s_dateOnce, ^{
        s_dateFormatter = [[NSDateFormatter alloc] init];
        [s_dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
        [s_dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    });
    
    //Note that the logging should not throw, as logging is heavily used in error conditions.
    //Hence, the checks below would rather swallow the error instead of throwing and changing the
    //program logic.
    if (logLevel <= ADAL_LOG_LEVEL_NO_LOG)
        return;
    if (!message)
        return;
    
    
    @synchronized(self)//Guard against thread-unsafe callback and modification of sLogCallback after the check
    {
        if (!(logLevel <= s_LogLevel && (s_LogCallback || s_NSLogging)))
        {
            return;
        }
        
        NSString* component = @"";
        if ([context respondsToSelector:@selector(component)])
        {
            id compRet = [context component];
            if ([compRet isKindOfClass:[NSString class]])
            {
                component = [NSString stringWithFormat:@" [%@]", compRet];
            }
        }
        
        NSString* correlationIdStr = @"";
        if (correlationId)
        {
            correlationIdStr = [NSString stringWithFormat:@" - %@", correlationId.UUIDString];
        }
        
        NSString* dateString =  [s_dateFormatter stringFromDate:[NSDate date]];
        if (s_NSLogging)
        {
            NSString* levelString = [self stringForLevel:logLevel];
            
            NSString* msg = [NSString stringWithFormat:@"ADAL " ADAL_VERSION_STRING " %@ [%@%@]%@ %@: %@", s_OSString, dateString, correlationIdStr,
                             component, levelString, message];
            
            //NSLog is documented as thread-safe:
            NSLog(@"%@", msg);
        }
        
        if (s_LogCallback)
        {
            NSString* msg = [NSString stringWithFormat:@"ADAL " ADAL_VERSION_STRING " %@ [%@%@]%@ %@", s_OSString, dateString, correlationIdStr, component, message];
            s_LogCallback(logLevel, msg, info, errorCode, userInfo);
        }
    }
}

+ (void)log:(ADAL_LOG_LEVEL)level
    context:(id)context
    message:(NSString *)message
  errorCode:(NSInteger)code
correlationId:(NSUUID*)correlationId
   userInfo:(NSDictionary *)userInfo
     format:(NSString *)format, ...
{
    va_list args;
    va_start(args, format);
    NSString* info = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    [self log:level context:context message:message errorCode:code info:info correlationId:correlationId userInfo:userInfo];
    SAFE_ARC_RELEASE(info);
}

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
        AD_LOG_WARN_F(@"Logging", nil, @"Cannot extract cpu type. Error: %d", result);
        return nil;
    }
    
    return (CPU_ARCH_ABI64 & cpuType) ? @"64" : @"32";
}

+ (NSDictionary*)adalId
{
    dispatch_once(&s_logOnce, ^{
#if TARGET_OS_IOS
        //iOS:
        UIDevice* device = [UIDevice currentDevice];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"iOS",
                                         ADAL_ID_VERSION:[ADLogger getAdalVersion],
                                         ADAL_ID_OS_VER:device.systemVersion,
                                         ADAL_ID_DEVICE_MODEL:device.model,//Prints out only "iPhone" or "iPad".
                                         }];
#elif TARGET_OS_WATCH
        WKInterfaceDevice* device = [WKInterfaceDevice currentDevice];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"watchOS",
                                         ADAL_ID_VERSION:[ADLogger getAdalVersion],
                                         ADAL_ID_OS_VER:device.systemVersion,
                                         ADAL_ID_DEVICE_MODEL:device.model,
                                         }];

#else
        NSOperatingSystemVersion osVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"OSX",
                                         ADAL_ID_VERSION:[NSString stringWithFormat:@"%d.%d", ADAL_VER_HIGH, ADAL_VER_LOW],
                                         ADAL_ID_OS_VER:[NSString stringWithFormat:@"%ld.%ld.%ld", (long)osVersion.majorVersion, (long)osVersion.minorVersion, (long)osVersion.patchVersion],
                                         }];
#endif
        NSString* CPUVer = [self getCPUInfo];
        if (![NSString adIsStringNilOrBlank:CPUVer])
        {
            [result setObject:CPUVer forKey:ADAL_ID_CPU];
        }
        
        s_adalId = result;
        SAFE_ARC_RETAIN(s_adalId);
    });
    
    return s_adalId;
}

+ (NSString*)getHash:(NSString*)input
{
    if (!input)
    {
        return nil;//Handle gracefully
    }
    const char* inputStr = [input UTF8String];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(inputStr, (int)strlen(inputStr), hash);
    NSMutableString* toReturn = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    SAFE_ARC_AUTORELEASE(toReturn);
    for (int i = 0; i < sizeof(hash)/sizeof(hash[0]); ++i)
    {
        [toReturn appendFormat:@"%02x", hash[i]];
    }
    return toReturn;
}

+ (NSString*) getAdalVersion
{
    return ADAL_VERSION_NSSTRING;
}

+ (void)logToken:(NSString*)token
       tokenType:(NSString*)tokenType
       expiresOn:(NSDate*)expiresOn
   correlationId:(NSUUID*)correlationId
{
    AD_LOG_VERBOSE_F(@"Token returned", nil, @"Obtained %@ with hash %@, expiring on %@ and correlationId: %@", tokenType, [self getHash:token], expiresOn, [correlationId UUIDString]);
}

+ (void)setIdValue:(NSString*)value
            forKey:(NSString*)key
{
    [self adalId];
    
    [s_adalId setObject:value forKey:key];
}

@end

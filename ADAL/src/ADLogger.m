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

static ADAL_LOG_LEVEL s_LogLevel = ADAL_LOG_LEVEL_ERROR;
static LogCallback s_LogCallback = nil;
static BOOL s_NSLogging = YES;

static NSMutableDictionary* s_adalId = nil;

static dispatch_once_t s_logOnce;

@implementation ADLogger

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

+ (NSString*)formatStringPerLevel:(ADAL_LOG_LEVEL)level
{
    {//Compile time check that all of the levels are covered below.
    int add_new_types_to_the_switch_below_to_fix_this_error[ADAL_LOG_LEVEL_VERBOSE - ADAL_LOG_LAST];
    #pragma unused(add_new_types_to_the_switch_below_to_fix_this_error)
    }
    
    switch (level) {
        case ADAL_LOG_LEVEL_ERROR:
            return @"ADAL [%@ - %@] ERROR: %@. Additional Information: %@. ErrorCode: %d.";
            break;
            
        case ADAL_LOG_LEVEL_WARN:
            return @"ADAL [%@ - %@] WARNING: %@. Additional Information: %@. ErrorCode: %d.";
            break;
            
        case ADAL_LOG_LEVEL_INFO:
            return @"ADAL [%@ - %@] INFORMATION: %@. Additional Information: %@. ErrorCode: %d.";
            break;
            
        case ADAL_LOG_LEVEL_VERBOSE:
            return @"ADAL [%@ - %@] VERBOSE: %@. Additional Information: %@. ErrorCode: %d.";
            break;
            
        default:
            return @"ADAL [%@ - %@] UNKNOWN: %@. Additional Information: %@. ErrorCode: %d.";
            break;
    }
}

+ (void)log:(ADAL_LOG_LEVEL)logLevel
    message:(NSString*)message
  errorCode:(NSInteger)errorCode
       info:(NSString*)info
correlationId:(NSUUID*)correlationId
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
        if (logLevel <= s_LogLevel && (s_LogCallback || s_NSLogging))
        {
            NSString* dateString =  [s_dateFormatter stringFromDate:[NSDate date]];
            if (s_NSLogging)
            {
                //NSLog is documented as thread-safe:
                NSLog([self formatStringPerLevel:logLevel], dateString, correlationId ?[correlationId UUIDString]:@"", message, info, errorCode);
            }
            
            if (s_LogCallback)
            {
                if (correlationId)
                {
                    s_LogCallback(logLevel, [NSString stringWithFormat:@"ADALiOS [%@ - %@] %@", dateString, [correlationId UUIDString], message], info, errorCode);
                }
                else
                {
                    s_LogCallback(logLevel, [NSString stringWithFormat:@"ADALiOS [%@] %@", dateString, message], info, errorCode);
                }
            }
        }
    }
}

+ (void)log:(ADAL_LOG_LEVEL)level
    message:(NSString*)message
  errorCode:(NSInteger)code
correlationId:(NSUUID*)correlationId
     format:(NSString*)format, ...
{
    va_list args;
    va_start(args, format);
    NSString* info = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    [self log:level message:message errorCode:code info:info correlationId:correlationId];
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
#if TARGET_OS_IPHONE
        //iOS:
        UIDevice* device = [UIDevice currentDevice];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"iOS",
                                         ADAL_ID_VERSION:[ADLogger getAdalVersion],
                                         ADAL_ID_OS_VER:device.systemVersion,
                                         ADAL_ID_DEVICE_MODEL:device.model,//Prints out only "iPhone" or "iPad".
                                         }];
#else
        NSDictionary *systemVersionDictionary = [NSDictionary dictionaryWithContentsOfFile:
                                                 @"/System/Library/CoreServices/SystemVersion.plist"];
        NSMutableDictionary* result = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         ADAL_ID_PLATFORM:@"OSX",
                                         ADAL_ID_VERSION:[NSString stringWithFormat:@"%d.%d", ADAL_VER_HIGH, ADAL_VER_LOW],
                                         ADAL_ID_OS_VER:[systemVersionDictionary objectForKey:@"ProductVersion"],
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

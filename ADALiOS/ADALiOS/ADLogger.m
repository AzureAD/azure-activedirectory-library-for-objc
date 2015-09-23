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

#import "ADAL.h"
#import "ADOAuth2Constants.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#include <CommonCrypto/CommonDigest.h>

static ADAL_LOG_LEVEL sLogLevel = ADAL_LOG_LEVEL_ERROR;
static ADLogCallback sLogCallback = nil;
static BOOL sNSLogging = YES;
static NSUUID* s_requestCorrelationId = nil;
static NSDateFormatter* s_logDateFormatter = nil;

@implementation ADLogger

+ (void)initialize
{
    NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    
    s_logDateFormatter = dateFormatter;
}

+ (void)setLevel: (ADAL_LOG_LEVEL)logLevel
{
    sLogLevel = logLevel;
}

+ (ADAL_LOG_LEVEL)getLevel
{
    return sLogLevel;
}

+ (void)setLogCallBack:(ADLogCallback)callback
{
    @synchronized(self)//Avoid changing to null while attempting to call it.
    {
        if (sLogCallback)
        {
            SAFE_ARC_BLOCK_RELEASE( sLogCallback );
        }
        sLogCallback = SAFE_ARC_BLOCK_COPY( callback );
    }
}

+ (ADLogCallback)getLogCallBack
{
    return sLogCallback;
}


+(void) setNSLogging: (BOOL) nslogging
{
    sNSLogging = nslogging;
}

+(BOOL) getNSLogging
{
    return sNSLogging;
}

+ (NSString*)stringPerLevel:(ADAL_LOG_LEVEL) level
{
    switch (level)
    {
        case ADAL_LOG_LEVEL_ERROR:      return @"ERROR";
        case ADAL_LOG_LEVEL_WARN:       return @"WARNING";
        case ADAL_LOG_LEVEL_INFO:       return @"INFO";
        case ADAL_LOG_LEVEL_VERBOSE:    return @"VERBOSE";
        default:    return @"UNKNOWN";
    }
}

+ (void)log:(ADAL_LOG_LEVEL)logLevel
    message:(NSString*)message
  errorCode:(NSInteger)errorCode
       info:(NSString*)info
{
    //Note that the logging should not throw, as logging is heavily used in error conditions.
    //Hence, the checks below would rather swallow the error instead of throwing and changing the
    //program logic.
    if (logLevel <= ADAL_LOG_LEVEL_NO_LOG)
        return;
    if (!message)
        return;
    
    if (logLevel <= sLogLevel)
    {
        
        NSString* dateString = [s_logDateFormatter stringFromDate:[NSDate date]];
        NSString* correlationId = [[ADLogger getCorrelationId] UUIDString];
        
        if (sNSLogging)
        {
            //NSLog is documented as thread-safe:
            NSLog(@"ADALiOS [%@ - %@] %@: %@. Additional Information: %@. ErrorCode: %ld.", [self stringPerLevel:logLevel], dateString, correlationId, message, info, (long)errorCode);
        }
        
        @synchronized(self)//Guard against thread-unsafe callback and modification of sLogCallback after the check
        {
            if (sLogCallback)
            {
                sLogCallback(logLevel, [NSString stringWithFormat:@"ADALiOS [%@ - %@] %@", dateString, correlationId, message], info, errorCode);
            }
        }
    }
}

+ (void)log:(ADAL_LOG_LEVEL)level
    message:(NSString*)message
  errorCode:(NSInteger)code
     format:(NSString*)format, ...
{
    va_list args;
    va_start(args, format);
    NSString* info = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    [self log:level message:message errorCode:code info:info];
    SAFE_ARC_RELEASE(info);
}

//Extracts the CPU information according to the constants defined in
//machine.h file. The method prints minimal information - only if 32 or
//64 bit CPU architecture is being used.
+(NSString*) getCPUInfo
{
    size_t structSize;
    cpu_type_t cpuType;
    structSize = sizeof(cpuType);
    
    //Extract the CPU type. E.g. x86. See machine.h for details
    //See sysctl.h for details.
    int result = sysctlbyname("hw.cputype", &cpuType, &structSize, NULL, 0);
    
    if (result)
    {
        AD_LOG_WARN_F(@"Logging", @"Cannot extract cpu type. Error: %d", result);
        return nil;
    }
    
    if (cpuType == CPU_TYPE_X86)
    {
        //The x86 architecture is typically 64 bit. Confirm here:
        cpu_type_t optionalValue;
        result = sysctlbyname("hw.optional.x86_64", &optionalValue, &structSize, NULL, 0);
        if (result == 0)
            return @"x86_64";
        else
            return @"x86";
    }

    
    return (CPU_ARCH_ABI64 & cpuType) ? @"arm64" : @"arm32";
}

+(NSDictionary*) adalId
{
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
    return result;
}

+(NSString*) getHash: (NSString*) input
{
    if (!input)
    {
        return nil;//Handle gracefully
    }
    const char* inputStr = [input UTF8String];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(inputStr, (int)strlen(inputStr), hash);
    NSMutableString* toReturn = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i = 0; i < sizeof(hash)/sizeof(hash[0]); ++i)
    {
        [toReturn appendFormat:@"%02x", hash[i]];
    }
    return toReturn;
}

+ (void)setCorrelationId:(NSUUID*)correlationId
{
    SAFE_ARC_RELEASE(s_requestCorrelationId);
    s_requestCorrelationId = correlationId;
    SAFE_ARC_RETAIN(s_requestCorrelationId);
}

+ (NSUUID*)getCorrelationId
{
    if (s_requestCorrelationId == nil)
    {
        s_requestCorrelationId = [NSUUID new];
    }
    
    return s_requestCorrelationId;
}

+(NSString*) getAdalVersion
{
    return [NSString stringWithFormat:@"%d.%d.%d", ADAL_VER_HIGH, ADAL_VER_LOW, ADAL_VER_PATCH];
}

+(void) logToken: (NSString*) token
       tokenType: (NSString*) tokenType
       expiresOn: (NSDate*) expiresOn
   correlationId: (NSUUID*) correlationId
{
    AD_LOG_VERBOSE_F(@"Token returned", @"Obtained %@ with hash %@, expiring on %@ and correlationId: %@", tokenType, [self getHash:token], expiresOn, [correlationId UUIDString]);
}

@end

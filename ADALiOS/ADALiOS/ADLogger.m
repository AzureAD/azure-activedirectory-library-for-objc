//  Created by Boris Vidolov on 10/25/13.
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

#import "ADALiOS.h"
#import "ADLogger.h"

ADAL_LOG_LEVEL sLogLevel = ADAL_LOG_LEVEL_ERROR;
LogCallback sLogCallback;
BOOL sNSLogging = YES;

@implementation ADLogger

+(void) setLevel: (ADAL_LOG_LEVEL)logLevel
{
    sLogLevel = logLevel;
}

+(ADAL_LOG_LEVEL) getLevel
{
    return sLogLevel;
}

+(void) setLogCallBack: (LogCallback) callback
{
    @synchronized(self)//Avoid changing to null while attempting to call it.
    {
        sLogCallback = callback;
    }
}

+(LogCallback) getLogCallBack
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

+(NSString*) formatStringPerLevel: (ADAL_LOG_LEVEL) level
{
    {//Compile time check that all of the levels are covered below.
    int add_new_types_to_the_switch_below_to_fix_this_error[ADAL_LOG_LEVEL_VERBOSE - ADAL_LOG_LAST];
    #pragma unused(add_new_types_to_the_switch_below_to_fix_this_error)
    }
    
    switch (level) {
        case ADAL_LOG_LEVEL_ERROR:
            return @"ADALiOS: ERROR: %@. Additional Information: %@. ErrorCode: %u.";
            break;
            
        case ADAL_LOG_LEVEL_WARN:
            return @"ADALiOS: WARNING: %@. Additional Information: %@. ErrorCode: %u.";
            break;
            
        case ADAL_LOG_LEVEL_INFO:
            return @"ADALiOS: INFORMATION: %@. Additional Information: %@. ErrorCode: %u.";
            break;
            
        case ADAL_LOG_LEVEL_VERBOSE:
            return @"ADALiOS: VERBOSE: %@. Additional Information: %@. ErrorCode: %u.";
            break;
            
        default:
            return @"ADALiOS: UNKNOWN: %@. Additional Information: %@. ErrorCode: %u.";
            break;
    }
}

+(void) log: (ADAL_LOG_LEVEL)logLevel
    message: (NSString*) message
  errorCode: (NSInteger) errorCode
additionalInformation: (NSString*) additionalInformation
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
        if (sNSLogging)
        {
            //NSLog is documented as thread-safe:
            NSLog([self formatStringPerLevel:logLevel], message, additionalInformation, errorCode);
        }
        
        @synchronized(self)//Guard against thread-unsafe callback and modification of sLogCallback after the check
        {
            if (sLogCallback)
            {
                sLogCallback(logLevel, message, additionalInformation, errorCode);
            }
        }
    }
}

@end

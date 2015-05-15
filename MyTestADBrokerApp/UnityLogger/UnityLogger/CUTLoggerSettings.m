/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: Settings object for the logger components.
 
 Owner: yiweizha
 Created: 10/06/2013
 */

#import "CUTLogger.h"
#import "CUTLoggerSettings.h"

@implementation CUTLoggerSettings

//
// init
//
- (id) init
{
    if (!(self = [super init])) { return nil; }
    
    // Set the default value for trace level mask
    _logLevelMask = CUTTraceLevelAssert | CUTTraceLevelError | CUTTraceLevelWarning | CUTTraceLevelInfo | CUTTraceLevelPerformance;

    // Set the default value for config mask
    _logConfigMask = CUTLogTimeStamp | CUTLogFileName | CUTLogFunction | CUTLogLineNumber | CUTLogThreadID;
    
    return self;
}

@end


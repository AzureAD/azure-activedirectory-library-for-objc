/*
 Copyright © Microsoft. All rights reserved.
 
 Synopsis:  Implementation of CUTLogger. It notifies its delegates (e.g. CUTFileLogger) to perform actual logging operation
 
 Owner: yiweizha
 Created: 10/06/2013
 */
#import "CUTLoggerImp.h"
#import "CUTLogWriter.h"

//Log level strings
NSString* const kCUTLogLevelInfo        = @"INFO";
NSString* const kCUTLogLevelWarning     = @"WARN";
NSString* const kCUTLogLevelError       = @"ERRO";
NSString* const kCUTLogLevelAssert      = @"ASSE";
NSString* const kCUTLogLevelVerbose     = @"VERB";
NSString* const kCUTLogLevelPerformance = @"PERF";
NSString* const kCUTLogLevelFunction    = @"FUNC";
NSString* const kCUTLogLevelMemory      = @"MEMO";

// Log event code strings
NSString *const kCUTLogEventDefault    = @"";
NSString *const kCUTLogEventStart      = @"Start";
NSString *const kCUTLogEventEnd        = @"End";
NSString *const kCUTLogEventCall       = @"Call";
NSString *const kCUTLogEventReturn     = @"Return";

//
// Remove the path info in the file name.
//
const char* logTrimmedFileName(const char* szFilePath)
{
    const char * psz = strrchr(szFilePath, '/');
    
    return psz ? psz + 1 : szFilePath;
}

//
// Get a string representation of a log level.
//
NSString * stringFromLogLevel(CUTTraceLevel level)
{
    switch (level)
    {
        case CUTTraceLevelInfo: return kCUTLogLevelInfo;
        case CUTTraceLevelWarning: return kCUTLogLevelWarning;
        case CUTTraceLevelError: return kCUTLogLevelError;
        case CUTTraceLevelVerbose: return kCUTLogLevelVerbose;
        case CUTTraceLevelAssert: return kCUTLogLevelAssert;
        case CUTTraceLevelPerformance: return kCUTLogLevelPerformance;
        case CUTTraceLevelFunction: return kCUTLogLevelFunction;
        case CUTTraceLevelMemory: return kCUTLogLevelMemory;
        default:
            CUTTrace(CUTTraceLevelError, kCUTLoggerDomain, @"TRACE_LEVEL %d unknown.", (int)level);
            break;
    }
    return nil;
}

//
// Get a string representation of a event code.
//
NSString * stringFromLogEventCode(CUTTraceEventCode eventCode)
{
    switch (eventCode)
    {
        case CUTTraceEventDefault: return kCUTLogEventDefault;
        case CUTTraceEventCall:    return kCUTLogEventCall;
        case CUTTraceEventReturn:  return kCUTLogEventReturn;
        case CUTTraceEventStart:   return kCUTLogEventStart;
        case CUTTraceEventEnd:     return kCUTLogEventEnd;
        default:
            CUTTrace(CUTTraceLevelError, kCUTLoggerDomain, @"TRACE_EVENT_CODE %d unknown.", (int)eventCode);
            break;
    }
    return nil;
}


@interface CUTLoggerImp ()

// Logger settings
@property (strong, nonatomic) CUTLoggerSettings *loggerSettings;

// Reference to the available implemented log writers
@property (strong, nonatomic) NSMutableArray *logWriters;

@end


@implementation CUTLoggerImp

//
//Write an event out to the log.
// If error is set, error details are appended to message.
// According to common SSP logger design, the format should be:
// {Time}\t{Level}\t{Event Code}\t{Domain}\t{Event ID}\t{Thread Info}\t{Activity}\t{Message}
//
- (void)traceWithFunctionName:(const char *)function
                       atLine:(long)line
                       inFile:(const char *)filename
                     forLevel:(CUTTraceLevel)level
                     inDomain:(NSString *)domain
                withEventCode:(CUTTraceEventCode)eventCode
                   andEventID:(NSUInteger)eventID
                 withActivity:(NSString *)activity
                  withMessage:(NSString *)message
                     andError:(NSError *)error
{
    NSString *updatedMessage = message;
    
    // only add the error details if error instance is set.
    if (error)
    {
        updatedMessage = [message stringByAppendingFormat:@"\n%@", [error description]];
        
        NSString *innerErrorDescription = [[error innerError] description];
        
        if (innerErrorDescription)
        {
            updatedMessage = [updatedMessage stringByAppendingFormat:@"\n Inner Error: %@", innerErrorDescription];
        }
    }
    
    [self traceWithFunctionName:function
                         atLine:line
                         inFile:filename
                       forLevel:level
                       inDomain:domain
                  withEventCode:eventCode
                     andEventID:eventID
                   withActivity:activity
                    withMessage:updatedMessage];
}

//
// Write an event out to the log.
// According to common SSP logger design, the format should be:
// {Time}\t{Level}\t{Event Code}\t{Domain}\t{Event ID}\t{Thread Info}\t{Activity}\t{Message}
//
- (void)traceWithFunctionName:(const char *)function
                       atLine:(long)line
                       inFile:(const char *)filename
                     forLevel:(CUTTraceLevel)level
                     inDomain:(NSString *)domain
                withEventCode:(CUTTraceEventCode)eventCode
                   andEventID:(NSUInteger)eventID
                 withActivity:(NSString *)activity
                  withMessage:(NSString *)message
{
    NSUInteger logLevelMask = self.loggerSettings.logLevelMask;
    NSUInteger logConfigMask = self.loggerSettings.logConfigMask;
    
    //Check if the level is within the mask
    if (level & logLevelMask)
    {
        CUTTraceInfo *traceInfo = [[CUTTraceInfo alloc] init];
        NSMutableString *formattedLog = [[NSMutableString alloc] init];
        
        if (traceInfo != nil)
        {
            //If enable logging time stamp, add it to the dictionary
            if (logConfigMask & CUTLogTimeStamp)
            {
                NSString *dateString = [NSDate stringFromUtcDate:[NSDate date] withFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
                traceInfo.dateString = dateString;
                [formattedLog appendFormat:@"%@\t", dateString];
            }
            else
            {
                [formattedLog appendFormat:@"\t"];
            }
            
            //Add level info to the dictionary
            NSString *logLevelString = stringFromLogLevel(level);
            
            if (logLevelString == nil)
            {
                logLevelString = @"Unknown Level";
            }
            traceInfo.levelInfo = logLevelString;
            [formattedLog appendFormat:@"%@", logLevelString];
            
            //Add event info to the dictionary
            NSString *logEventCodeString = stringFromLogEventCode(eventCode);
            
            if (logEventCodeString == nil)
            {
                logEventCodeString = @"Unknown Event Code";
            }
            traceInfo.eventCodeString = logEventCodeString;
            [formattedLog appendFormat:@"\t%@", logEventCodeString];
            
            //Add domain info to the dictionary
            if (domain == nil)
            {
                domain = @"Unknown domain";
            }
            traceInfo.domain = domain;
            [formattedLog appendFormat:@"\t%@", domain];
            
            //Add event ID to the dictionary
            traceInfo.eventIdString = [[NSString alloc] initWithFormat:@"%lu",(unsigned long)eventID] ;
            [formattedLog appendFormat:@"\t%lu", (unsigned long)eventID];
            
            //If enable logging thread ID, add it
            if (logConfigMask & CUTLogThreadID)
            {
                NSString *threadId = [[NSThread currentThread] threadId];
                traceInfo.threadInfo = [NSString stringWithFormat:@"TID=%@", threadId];
                [formattedLog appendFormat:@"\t%@", traceInfo.threadInfo];
            }
            else
            {
                [formattedLog appendFormat:@"\t"];
            }
            
            // Add activity string
            if (activity != nil)
            {
                traceInfo.threadInfo  = activity;
                [formattedLog appendFormat:@"\t%@\t", activity];
            }
            else
            {
                [formattedLog appendFormat:@"\t\t"];
            }
            
            //If enable logging file name, add it to the dictionary
            if (logConfigMask & CUTLogFileName)
            {
                traceInfo.fileName = [NSString stringWithUTF8String:logTrimmedFileName(filename)];
                [formattedLog appendFormat:@" %s:", logTrimmedFileName(filename)];
            }
            
            //If enable logging line number, add it to the dictionary
            if (logConfigMask & CUTLogLineNumber)
            {
                traceInfo.lineNumber = [NSString stringWithFormat:@"%ld",line] ;
                [formattedLog appendFormat:@" %ld", line];
            }
            
            //If enable logging function name, add it to the dictionary
            if (logConfigMask & CUTLogFunction)
            {
                traceInfo.functionName = [NSString stringWithUTF8String:function];
                [formattedLog appendFormat:@" (%s)", function];
            }
            
            //Add the formatted logging string to the dictionary
            if (message != nil)
            {
                traceInfo.message  = message;
                [formattedLog appendFormat:@" %@", message];
            }
            else
            {
                printf("No message for logging");
            }
            
            [formattedLog replaceOccurrencesOfString:@"<" withString:@"[" options:NSCaseInsensitiveSearch range:NSMakeRange(0,formattedLog.length)];
            [formattedLog replaceOccurrencesOfString:@">" withString:@"]" options:NSCaseInsensitiveSearch range:NSMakeRange(0,formattedLog.length)];
            
            //Finally add the whole formatted string
            traceInfo.formattedString = formattedLog;
            
            //Notify each delegate to do the logging, dispatch the job to sequential queue
            for (id<CUTLogWriter> logger in self.logWriters)
            {
                [logger writeLogWithInfo:traceInfo];
            }
            
            // Print to console as well.
            printf("%s\n", [formattedLog UTF8String]);
        }
    }
}

//
// Check assertion and return YES/NO.
//
- (BOOL) assertCondition:(BOOL)condition
        withFunctionName:(const char *)function
                  atLine:(long)line
                  inFile:(const char *)filename
                inDomain:(NSString *)domain
           withEventCode:(CUTTraceEventCode)eventCode
              andEventID:(NSUInteger)eventID
            withActivity:(NSString *)activity
             withMessage:(NSString *)message
{
    if (condition)
    {
        return YES;
    }
    else
    {
        //
        //For release version, we may just log the assert info
        //
        [self traceWithFunctionName:function
                             atLine:line
                             inFile:filename
                           forLevel:CUTTraceLevelAssert
                           inDomain:domain
                      withEventCode:eventCode
                         andEventID:eventID
                       withActivity:activity
                        withMessage:message];
        
        //
        //IF not unit testing and in debug version, throw exception here, for release just trace.
        //
#if !defined(UNIT_TESTING) && defined(DEBUG)
        [NSException raise:@"*** ASSERT ***" format:@"***   End  ***"];
#endif
        return NO;
    }
}


//
// initWithLoggerSettings
//
- (id)initWithLoggerSettings:(CUTLoggerSettings *) loggerSettings
{
    if (!(self = [super init])) { return nil; }
    
    _logWriters = [[NSMutableArray alloc] init];
    
    _loggerSettings = loggerSettings;
    
    return self;
}

//
// setLoggerSettings
//
- (void)setLoggerSettings:(CUTLoggerSettings *) loggerSettings
{    
    _loggerSettings = loggerSettings;
}

//
// Add a log writer instance.
//
- (void) addLogWriter:(id<CUTLogWriter>) instance
{
    @synchronized(self)
    {
        if (instance != nil)
        {
            [self.logWriters addObject:instance];
        }
    }
}

- (id<CUTLogWriter>) getLogWriter
{
    @synchronized(self)
    {
        if (self.logWriters.count > 0)
        {
            return [self.logWriters objectAtIndex:0];
        }
        
        return nil;
    }
}

//
// clearLogs
//
- (void)clearLogs
{
    for (id<CUTLogWriter> logWriter in self.logWriters)
    {
        [logWriter clearLogs];
    }
    
    return;
}

@end

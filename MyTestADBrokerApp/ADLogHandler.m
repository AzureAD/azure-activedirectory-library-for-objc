//
//  ADLogHandler.m
//  MyTestADBrokerApp
//
//  Created by Kanishk Panwar on 5/14/15.
//  Copyright (c) 2015 Microsoft Corp. All rights reserved.
//

#import "ADLogHandler.h"
#import <UnityLogger/UnityLogger.h>

@implementation ADLogHandler


-(id) init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initInternal
{
    self = [super init];
    if (self)
    {
        id<CUTLogger> logger;
        id<CUTLogWriter> circularFileLogWriter;
        
        CUTLoggerSettings* loggerSettings = [CUTLoggerSettings new];
        loggerSettings.logLevelMask = CUTTraceLevelVerbose;
        loggerSettings.logConfigMask = CUTLogTimeStamp | CUTLogFunction | CUTLogLineNumber | CUTLogThreadID;
        
        logger = [CUTLibrary loggerWithSettings:loggerSettings];
        CUTCircularFileLogWriterSettings* settings = [CUTCircularFileLogWriterSettings new];
        
        settings.logFileNamePrefix=@"authenticator-";
        settings.logDirectory = [NSSearchPathForDirectoriesInDomains (NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
        settings.maxLogFileSize = 1000000; //1MB
        settings.numberOfLogFiles = 2;
        
        circularFileLogWriter = [CUTLibrary circularFileLogWriterWithSettings:settings];
        [logger addLogWriter:circularFileLogWriter];
        
        if (![CUTLibrary sharedLogger])
        {
            [CUTLibrary setSharedLogger:logger];
        }
        
        [WorkPlaceJoin WorkPlaceJoinManager].loggerDelegate = self;
        
        //configure BROKER/ADAL logger
        [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];
        [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode){
            
            CUTTraceLevel traceLevel = [self traceLevelFromAdalLogLevel:logLevel];
            CUTTrace(traceLevel, @"ADBroker", @"%@, %@, error code: %ld", message, additionalInformation, (long)errorCode);
        }];
    }
    return self;
}

+ (id)configureLoggers
{
    static ADLogHandler *instance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] initInternal];
    });
    
    return instance;
}


//
// workplaceClient:logMessage:
// Called when workplace join is logging a messgge.
//
- (void)workplaceClient:(WorkPlaceJoin*)workplaceClient
             logMessage:(NSString*)logMessage;
{
    CUTTrace(CUTTraceLevelVerbose, @"WorkplaceJoin", @"%@", logMessage);
}

-(CUTTraceLevel) traceLevelFromAdalLogLevel:(ADAL_LOG_LEVEL) adalLogLevel
{
    switch (adalLogLevel)
    {
        case ADAL_LOG_LEVEL_ERROR:   return CUTTraceLevelError;
        case ADAL_LOG_LEVEL_WARN:    return CUTTraceLevelWarning;
        case ADAL_LOG_LEVEL_INFO:    return CUTTraceLevelInfo;
        case ADAL_LOG_LEVEL_VERBOSE: return CUTTraceLevelVerbose;
        default:
            CUTTrace(CUTTraceLevelError, kCUTLoggerDomain, @"ADAL_LOG_LEVEL %lu unknown.", (unsigned long)adalLogLevel);
            break;
    }
    
    return CUTTraceLevelVerbose;
}

@end

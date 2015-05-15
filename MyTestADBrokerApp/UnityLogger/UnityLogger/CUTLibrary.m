/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  Inculdes the factory constructor for loggers and other initialize function for library.
 
 Owner:     Yiwei Zhang
 Created:   10/10/2013
 */

#import "CUTLibrary.h"
#import "CUTLoggerImp.h"
#import "CUTFileLogWriter.h"
#import "CUTFileManagerImp.h"

// A gloabal logger to be used for all components within the library
static id<CUTLogger> g_sharedLoggerInstance = nil;


@implementation CUTLibrary

#pragma mark - factory constructors

//
// create CUTLoggerImp with settings
//
+(id<CUTLogger>) loggerWithSettings:(CUTLoggerSettings *)loggerSettings
{
    return [[CUTLoggerImp alloc] initWithLoggerSettings:loggerSettings];
}

//
// create CUTFileLogWriter with settings
//
+(id<CUTLogWriter>) circularFileLogWriterWithSettings:fileLogWriterSettings
{
    return [[CUTFileLogWriter alloc] initWithSettings:fileLogWriterSettings];
}

//
// loggerWithLoggerSettings:fileLoggerSettings:
//
+(id<CUTLogger>) loggerWithLoggerSettings:(CUTLoggerSettings *)loggerSettings
               circularFileLoggerSettings:(CUTCircularFileLogWriterSettings *)fileLogWriterSettings
{
    CUTFileLogWriter *fileLogWriter = [[self class] circularFileLogWriterWithSettings:fileLogWriterSettings];
    CUTLoggerImp *logger = [[self class ]loggerWithSettings:loggerSettings];
    
    [logger addLogWriter:fileLogWriter];
    return logger;
}

//
// setSharedLogger
//
+(void) setSharedLogger:(id<CUTLogger>)logger
{
    @synchronized(self)
    {
        NSAssert(g_sharedLoggerInstance == nil, @"Resetting logger is not allowed!");
        g_sharedLoggerInstance = logger;
    }    
}

//
// sharedLogger
//
+(id<CUTLogger>) sharedLogger
{
    @synchronized(self)
    {
        return g_sharedLoggerInstance;
    }
}

@end

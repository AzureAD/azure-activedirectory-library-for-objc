/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  Inculdes the factory constructor for loggers and other initialize function for library.
 
 Owner:     Yiwei Zhang
 Created:   10/10/2013
 */

#import <Foundation/Foundation.h>

#import "CUTLogger.h"
#import "CUTLoggerSettings.h"
#import "CUTLogWriter.h"
#import "CUTCircularFileLogWriterSettings.h"
#import "CUTFileManager.h"

@interface CUTLibrary : NSObject

/**
 @brief Factory constructor that creates a logger instance
 @param  loggerSettings  Settings object for logger.
 @return Logger instance
 */
+(id<CUTLogger>) loggerWithSettings:(CUTLoggerSettings *)loggerSettings;

/**
 @brief Factory constructor that creates circular file log writer
 @param  fileLogWriterSettings    Settings object for file log writer.
 @return File log writer instance
 */
+(id<CUTLogWriter>) circularFileLogWriterWithSettings:(CUTCircularFileLogWriterSettings *)fileLogWriterSettings;

/**
 @brief Factory constructor that creates a logger instance with a circular file log writer instance added as its listener
 @param  loggerSettings                   Settings object for logger.
 @param  circularFileLogWriterSettings    Settings object for circular file log writer.
 @return Logger instance
 */
+(id<CUTLogger>) loggerWithLoggerSettings:(CUTLoggerSettings *)loggerSettings
               circularFileLoggerSettings:(CUTCircularFileLogWriterSettings *)fileLogWriterSettings;

/**
 @brief We keep a global logger for tracing within the library and this logger instance is supplied from client
        So the client needs to call this function to impose the logger otherwise nothing will be traced
 @param logger  Instance of the shared logger.
 @note  We do not support resetting the logger. The logger is allowed to be set only once, otherwise will raise assertion 
 */
+(void) setSharedLogger:(id<CUTLogger>)logger;

/**
 @brief Get the shared logger instance set by the client
 @return Instance of the shared logger. If no logger is set, returns nil
 */
+(id<CUTLogger>) sharedLogger;

@end


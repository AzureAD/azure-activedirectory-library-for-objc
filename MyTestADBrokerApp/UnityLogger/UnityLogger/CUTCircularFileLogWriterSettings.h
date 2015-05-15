/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: Settings object for the file logger components.
 
 Owner: yiweizha
 Created: 10/06/2013
 */

#import <Foundation/Foundation.h>

#define CUT_LOGFILE_GUID @"066B69C4-B148-49CC-8C5A-6D0B3C45A307"

/**
 @details  Settings object for the circular file log writer.
 We will have a number of log files working in a circular order to take logs
 So the each log file name will have the format "(prefix)<CUT_LOGFILE_GUID>_<log number>.txt"
 */
@interface CUTCircularFileLogWriterSettings : NSObject

/** @brief Prefix of the log file name */
@property (nonatomic, strong) NSString * logFileNamePrefix;

/** @brief Maximum size of log file */
@property (nonatomic, assign) NSUInteger maxLogFileSize;

/** @brief Number of log files */
@property (nonatomic, assign) NSUInteger numberOfLogFiles;

/** @brief Directory of log file in whole path */
@property (nonatomic, strong) NSString * logDirectory;

@end


/*
 Copyright © Microsoft. All rights reserved.
 
 Synopsis:  Implementation of CUTLogWriter that writes the log to plain text file
 instance.
 
 Owner: yiweizha
 Created: 10/06/2013
 */

#import "CUTCircularFileOperator.h"
#import "CUTFileLogWriter.h"

//
// Extension of text log file
//
NSString *const kCUTLogFileExtension = @"txt";

//
//Name of the file log sequential queue
//
const char *kCUTFileLogQueueName = "CUTFileLoggerQueue";

@implementation CUTTraceInfo
@end

@interface  CUTFileLogWriter ()


@property (nonatomic) unsigned long long fileSizeInBytes;

@property (strong,nonatomic) NSString *currentFilename;

//
//File handler of current log file
//
@property (strong,nonatomic) NSFileHandle *logFileHandle;

//
// private reference to the sequential logging dispatch queue
//
@property (strong, nonatomic) dispatch_queue_t fileLoggerQueue;

//
// File manager for logger
//
@property (strong, nonatomic, readonly) NSFileManager *fileManager;

//
// File logger settings
//
@property (strong, nonatomic, readonly) CUTCircularFileLogWriterSettings *fileLoggerSettings;

//
// Log file name
//
@property (strong, nonatomic, readonly) NSString *logFileName;

@end

@implementation CUTFileLogWriter

//
// initWithSettingsProvider
//
- (id)initWithSettings:(CUTCircularFileLogWriterSettings *) fileLoggerSettings
{
    if (!(self = [super init])) { return nil; }
    
    _fileLoggerQueue = dispatch_queue_create(kCUTFileLogQueueName, DISPATCH_QUEUE_SERIAL);
    _fileManager = [NSFileManager defaultManager];
    
    _fileLoggerSettings = fileLoggerSettings;
    _logFileName = [NSString stringWithFormat:@"%@%@", fileLoggerSettings.logFileNamePrefix, CUT_LOGFILE_GUID];
    
    // Only open log file once and keep use this log file during the whole APP session
    _logFileHandle = [self openLogFile];
    _fileSizeInBytes = [CUTCircularFileOperator getCurrentFilesizeInBytes:_currentFilename
                                       withFileManager:self.fileManager];
    return self;
}

//
// This function is only called once in the init, so it is thread safe
// It open the latest log file for writing. If its size reaches limit, create a new log file or overwrite the oldes one
// We will keep writing to the same log file during the whole session of the APP unless clear log is called
//
-(NSFileHandle *) openLogFile
{
    NSString *fileName = [CUTCircularFileOperator fileNameToOpenInCircularWithFileManager:self.fileManager
                                                                             andDirectory:self.fileLoggerSettings. logDirectory
                                                                              andFileName:self.logFileName
                                                                         andFileExtension:kCUTLogFileExtension
                                                                          andMaxFileNumber:self.fileLoggerSettings.numberOfLogFiles
                                                                             andSizeLimit:self.fileLoggerSettings.maxLogFileSize
                                                                             andAppending:nil];
    self.currentFilename = fileName;
    return [NSFileHandle fileHandleForWritingAtPath:fileName];
}


//
// Dispatch the logging job on its sequential queue
//
- (void)writeLogWithInfo:(CUTTraceInfo *)userInfo
{
    @synchronized(self.fileLoggerQueue)
    {
        if(userInfo.formattedString)
        {
            self.fileSizeInBytes+=[userInfo.formattedString dataUsingEncoding:NSUTF8StringEncoding].length;
        }
        
        if(self.fileSizeInBytes >= self.fileLoggerSettings.maxLogFileSize)
        {
            [self.logFileHandle closeFile];
            self.logFileHandle = nil;
            self.fileSizeInBytes = 0;
            self.logFileHandle = [self openLogFile];
        }
        
        dispatch_async(self.fileLoggerQueue, ^{
            [self writeLogToFileWithInfo:userInfo.formattedString];
        });
    }
}

//
// Write the log info to text file. In order to ensure the correct order when
// writing logs, we need to use a sequential queue.
// This function is thread safe
//
-(void)writeLogToFileWithInfo:(NSString *)formattedLog
{
    if (formattedLog == nil)
    {
        printf("Error: The input logging string is NULL!\n");
        return;
    }
    
    if (self.logFileHandle == nil)
    {
        printf("Error: The log file hanlder is NULL!\n");
        return;
    }
    
    formattedLog = [formattedLog stringByAppendingFormat:@"\n"];
    
    @try
    {
        [self.logFileHandle seekToEndOfFile];
        [self.logFileHandle writeData:[formattedLog dataUsingEncoding:NSUTF8StringEncoding]];
    }
    @catch (NSException *ex)
    {
        printf("Error writing log file: %s\n", [formattedLog UTF8String]);
    }
}

//
// Get the data within all the log files, from oldest to latest
//
-(void) fetchLogDataWithCompletion:(void (^)(NSData *, NSStringEncoding, NSError *))completion
{
    if (completion != nil)
    {
        dispatch_async(self.fileLoggerQueue, ^{
            NSError *error = nil;
            NSData *logData = [CUTCircularFileOperator dataFromCombinedFilesWithFileManager:self.fileManager
                                                                               andDirectory:self.fileLoggerSettings.logDirectory
                                                                                andFileName:self.logFileName
                                                                           andFileExtension:kCUTLogFileExtension
                                                                           andMaxFileNumber:self.fileLoggerSettings.numberOfLogFiles
                                                                                  withError:&error];
            completion(logData, NSUTF8StringEncoding, error);
        });
    }
}

//
// removeLogFiles
//
-(void) removeLogFiles
{
    // First, close file hanlder and set it to nil
    [self.logFileHandle closeFile];
    self.logFileHandle = nil;
    
    for (NSUInteger i = 0; i < self.fileLoggerSettings.numberOfLogFiles; i++)
    {
        NSString *fileName = [self.fileLoggerSettings.logDirectory stringByAppendingPathComponent:
                    [NSString stringWithFormat:kCUTCircularFileNameFormat, self.logFileName, i, kCUTLogFileExtension]];
        
        if ([self.fileManager fileExistsAtPath:fileName])
        {
            [self.fileManager removeItemAtPath:fileName error:nil];
        }
    }
    
    self.logFileHandle = [self openLogFile];
}

//
// Remove all log data
//
-(void) clearLogs
{
    dispatch_async(self.fileLoggerQueue, ^{
        [self removeLogFiles];
    });
}

@end

/*
 Copyright © 2012 Microsoft. All rights reserved.
 
 Synopsis: a protocol for file actions. One implementaion will be used for mocks and the other as a wrapper around NSFileManager
 
 Owner: Izik Lisbon
 Created: 02/21/2013
 */

#import <Foundation/Foundation.h>
@protocol CUTFileManager <NSObject>

/** @brief Gets the application support folder */
- (NSString *)appSupportFolderPath;

/**
 @details verify if a file exists
 @param filePath Gets the path to the file.
 */
-(BOOL)fileExistsAtPath:(NSString *)path;

/**
 @details get all the file attributes.
 @param filePath Gets the path to the file
 @param error Holds the error.
 */
-(NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error;

/**
 @details get the size of the file.
 @param filePath Gets the path to the file
 @param error Holds the error.
 */
-(NSUInteger)fileSizeInBytes:(NSString*)filePath error:(NSError **)error;

/**
 @brief Utility to create temporary file path
 @param filename Filename in temp directory
 @return Full path to temporary file.
 */
- (NSString *)filePathInTempForFilename:(NSString *)filename;

/**
 @details Get dictionary content from a file.
 @param path Path to the file.
 @param encoding Encoding to use to convert the file data to string.
 @param error Holds the error.
 */
- (NSDictionary *)dictionaryContentAtFile:(NSString *)path
                                    error:(NSError **)error;

/**
 @details Write a dictionary to a file.
 @param filePath Path to the file.
 @param encoding Encoding to use to convert the file data to string.
 @return Nil indicates success, otherwise an error.
 */
- (NSError *)writeDictionaryContent:(NSDictionary *)content
                        ToFile:(NSString *)path
                    atomically:(BOOL)useAuxiliaryFile;

/**
 @details Write a dictionary to a file.
 @param content  Content to write to the file
 @param path Path to the file.
 @param excludedFromBackup Yes to exclude from iCloud backup
 @return Nil indicates success, otherwise an error.
 */
- (NSError *)writeDictionaryContent:(NSDictionary *)content
                             ToFile:(NSString *)path
            shouldExcludeFromBackup:(BOOL)excludeFromBackup
                         atomically:(BOOL)useAuxiliaryFile;

/**
 @brief Utility to delete a file at a path.
 @param path The path of the file to be deleted
 @return Nil indicates success, otherwise an error.
 */
- (NSError *)deleteFile:(NSString *)path;

/**
 @brief Create a file at specified path with data
 @param filePath Path to the file.
 @param data Data to be written to file, it can be nil.
 @param attr Holds file attributes. 
 @return YES if the file created successfully. Returns NO if an error occurred.
 */
- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr;

/**
 @brief Create a directory at specified path
 @param path Path to the directory
 @param createIntermediateDirectories Indicates whether to create intermediate directories
 @param attributes Holds directory attributes.
 @param error Error if one occurred.
 @return YES if the file created successfully. Returns NO if an error occurred.
 */
- (BOOL)createDirectoryAtPath:(NSString*)path
  withIntermediateDirectories:(BOOL)createIntermediateDirectories
                   attributes:(NSDictionary *)attributes
                        error:(NSError **)error;

@end

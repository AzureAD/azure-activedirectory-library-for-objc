/*
 Copyright © 2013 Microsoft. All rights reserved.
 
 Synopsis: Contains categories for common utility library
 
 Owner: yiweizha
 Created: 9/26/2013
 */

#import <Foundation/Foundation.h>

@interface NSString (CUTCategories)

/**
 @details return YES if substring is contained in the string
 @param substring The substring to be searched
 @return YES if substring is contained, otherwise NO
 */
-(BOOL)containsString:(NSString*)substring;

/**
 @details return YES if string contains a given string, ignoring case or not.
 @param substring The substring to be searched
 @param ignoreCase Ignore case or not
 @return YES if substring is contained, otherwise NO
 */
-(BOOL)containsString:(NSString *)aString
         ignoringCase:(BOOL)ignoreCase;

/**
 @details Checks if a string starts with a particular substring.
 @param aString    The substring that might appear at the beginning of the string.
 @param ignoreCase NO for case sensitive comparison, YES for case insensitive
 @return YES if the string begins with aString, NO otherwise.
 */
- (BOOL)hasPrefix:(NSString *)aString
     ignoringCase:(BOOL)ignoreCase;

/**
 @brief Format a bool to Yes and No
 @param val The boolean value
 @return The string which is "YES" or "NO" based on input value
 */
+ (NSString *)stringFromBool:(BOOL)val;

/**
 @brief Check if a string equals a given string, iggnoring case or not
 @param aString The string to compare
 @param ignoreCase Ignoring case or not
 @return YES if string a given string is equal, ignoring case or not.
 */
-(BOOL)isEqualToString:(NSString *)aString
          ignoringCase:(BOOL)ignoreCase;

/**
 @brief Check if a string is a valid Guid
 @return YES if string is a valid Guid.
 @note Only accept guid in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX without brackets
 */
- (BOOL)isValidGuid;

/**
 @brief Check if a string is an empty Guid
 @return YES if string is equal to the string 00000000-0000-0000-0000-000000000000 or {00000000-0000-0000-0000-000000000000}
 */
- (BOOL)isEmptyGuid;

/**
 @brief Format a NSUInteger as a string.
 @param value The NSUInteger value
 @return The string from value
 */
+ (NSString *)stringWithUnsignedInteger:(NSUInteger)value;

/**
 @brief Adds all percent escapes necessary to convert the receiver into a legal URL string.
 @details Currently the stringByAddingPercentEscapesUsingEncoding method does not encode special characters such as !*+ etc. This is a work arround to force the enocoding for all special characters.
 @param enc The string encoding format
 @return The string with percent escapes added
 */
- (NSString *)stringByAddingPercentEscapesIncludingAllLegalURLCharactersUsingEncoding:(NSStringEncoding)enc;

/**
 @brief Replaces all percent escapes in a string, and also treats "+" as a space.
 @param enc The string encoding format
 @return The string with percent escapes replaced
 */
- (NSString *)stringByReplacingPercentEscapesIncludingPlusAsASpaceUsingEncoding:(NSStringEncoding)enc;

/**
 @brief Converts key value pairs as a URL query. Values are URL encoded. Ex. key1=value1&key2=value2.
 @param dict The dictionary to be converted.
 @return The string that contains url query
 */
+ (NSString *)stringWithURLQueryDictionary:(NSDictionary *)dict;

/**
 @brief Compares two strings treating them as versions (ex: 1.0, 2.3.1, ...)
 @param version The version to compare the strings to.
 @return NSOrderedAcending if self < version, NSOrderedSame if self == version, NSOrderedDescending if self > version
 @note There is no special validations on the version components, each component is compared after sending - [NSString integerValue]
 @note If the versions have a different amount of components, missing components will be treated as '0'. For example: 1.0 == 1.0.0 and 1.0 < 1.0.1
 */
- (NSComparisonResult)compareToVersion:(NSString *)version;

/**
 @brief Returns the masked string value that represents the presence of the string. The format of the string is '***(number of masked characters)'
 @return The masked string value that represents the presence of the string 
 */
- (NSString *)stringByMaskingCharacters;

/**
 @brief Returns the masked string value that represents the string leaving number of unmasked characters to the end. A sample of format: '***(number of masked characters)xxxx'
 @param  numberOfCharacters  The number of characters to be unmasked to the end of string
 @return The maksed string value that represents the string leaving number of unmasked characters to the end
 */
- (NSString *)stringByMaskingCharactersWithUnmaskedCharactersToEnd:(NSUInteger)numberOfCharacters;

/**
 @brief Returns true if the string is a secure url
 @return YES if url is secure, otherwise NO
 */
- (BOOL) isSecureURL;

/**
 @brief Returns true if the domain is a surfix of self(string) or self with a dot prefix
 @param  cookieDomain  The domain string of the cookie
 @return YES if it contains the domain, otherwise NO
 */
- (BOOL) containsCookieDomain:(NSString *)cookieDomain;

@end

@interface NSArray (CUTCategories)

/**
 @brief First object that matches the given predicate block
 @param predicate Condition to evaluate each object in the array.
 @return First object matching predicate.
 */
- (id)firstObjectMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate;

/**
 @brief Get an array of objects where each entry meets the predicate condition
 @param predicate Condition to evaluate for each item in current array.
 @return Array of objects matching predicate block.
 */
- (NSArray *)objectsMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate;

/**
 @brief Determine if an object is present in an array using a custom predicate block.
 @param predicate The predicate block used to determine if the object is in the array.
 @return YES if the object was found, NO otherwise.
 */
- (BOOL)containsObjectMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate;

/**
 @brief Returns an array that contains all the string values in the current array, but masked by using [NSString stringByMaskingCharacters].
 @note If an object in the array is not an NSString, it will be skipped and not added to the new array.
 @return The new array with masked values.
 */
- (NSArray *)arrayByMaskingStringValues;

@end


@interface NSMutableArray (CUTCategories)

/**
 @brief Move an object at a current index to a new position in the array.
 @param fromIndex Index of object to move
 @param destinationIndex Index to move object at fromIndex to.
 */
- (void)moveObjectAtIndex:(NSUInteger)fromIndex
                  toIndex:(NSUInteger)destinationIndex;

/**
 @brief Remove the object that matches the predicate.
 @param predicate The predicate to check
 @return Number of objects that removed
 */
- (NSUInteger)removeObjectsMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate;

/**
 @brief Add an object to an array. If the value is nil ignores it.
 @param obj The object to add
 @return return YES if values was added.
 */
- (BOOL)addObjectIfNotNil:(id)obj;

@end


@interface NSFileManager (CUTCategories)

/**
 @details return the file's size
 @param filePath  The path of file
 @param err Holds the error that may occur
 @return The file size in bytes
 */
+(NSUInteger)fileSizeInBytes:(NSString*)filePath error:(NSError **)err;

/**
 @details return the caches directory
 @return The Caches directory
 */
+(NSString *)cachesDirectory;

/**
 @brief Generate the full path with based directory and relative path.
 @param baseDirectory Base directory
 @param relativePath  Relative path to be added to base directory
 @return Full path that consists of based directory and relative path
 */
+ (NSString *)directoryWithBaseDirectory:(NSSearchPathDirectory)baseDirectory relativePath:(NSString *)relativePath;

@end

@interface NSData (CUTCategories)

/**
 @details Returns a string after running MD5 algorithm on the current data.
 @return The MD5 string
 */
- (NSString*)md5;

/**
 @details Conversion method from kilobytes to bytes.
 @param numberOfKilobytes The number of kilobytes to be converted to bytes.
 @return The number of bytes.
 */
+ (NSUInteger)bytesFromKilobytes:(NSUInteger)numberOfKilobytes;

@end

@interface NSObject (CUTCategories)

/**
 @details Returns nil if the value is nil or NSNull otherwise a value
 @param   aValue  Input instance which could be nil or NSNull
 @return  Nil if input is nil or NSNull. Otherwise the original input
 */
+(id)getNilOrValue:(id)aValue;

/**
 @details Returns NSNull if the value is nil or NSNull otherwise the value
 @param   aValue  Input instance which could be nil or NSNull
 @return  NSNull if input is nil or NSNull. Otherwise the original input
 */
+(id)getNSNullOrValue:(id)aValue;

@end


@interface NSDate(CUTCategories)

/**
 @details Returns the utc date by trying with the following formats in order: "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", "yyyy-MM-dd'T'HH:mm:ss'Z'".
 @param   string  String that contains date
 @return  The utc NSDate instance
 */
+ (NSDate *)utcDateFromString:(NSString *)string;

/**
 @details Returns the utc date with the specified format.
 @param   string String that contains date
 @param   format String that contains date format
 @return  The utc NSDate instance
 */
+ (NSDate *) utcDateFromString:(NSString *)string
                    withFormat:(NSString *)format;

/**
 @details Returns a string representing the date in the UTC time zone with the specified format.
 @param date   The date to get the UTC string from.
 @param format The format of the date string.
 @return The string representing the date in the UTC time zone.
 */
+ (NSString *)stringFromUtcDate:(NSDate *)date
                     withFormat:(NSString *)format;


@end

@interface NSDictionary (CUTCategories)

/**
 @brief Get an object in the dictionary and get a value if the value is of type of the specified class
 @param aKey Dictionary key
 @param aClass Class to check if value is subclass of
 @return Nil if key does not exist, value is NSNull or value is not of type aClass.
 */
- (id)objectForKey:(id)aKey ofClass:(Class) aClass;

/**
 @details returns the value if the key was present in the dictionary and the value was NOT nil, returns defaultValue otherwise. Returns nil, if the key existed but the value was NSNull. The keyExists parameter is optional, if provided it will be YES if key was found in the dictionary and NO otherwise.
 @param aKey   The key to be searched.
 @param defaultValue The default value.
 @param keyExists  Indicates if key exists in the dictionary
 @return The value of the key.
 */
- (id)objectForKey:(id)aKey withDefault:(id)defaultValue keyExists:(BOOL *)keyExists;

/**
 @details Returns an object for a string key, where the key can be case sensitive or not.
 @param key        The key into the dictionary. Must be an NSString.
 @param ignoreCase YES if the key should be case insensitive, NO if it should be case sensitive.
 @return The value in the dictionary, nil if it is not found.
 @note If there are multiple matches, then this will return the first one found.
 @note For large dictionaries, this method may be slow in performance since it iterates through all of the dictionaries keys.
 */
- (id)objectForStringKey:(NSString *)key ignoringCase:(BOOL)ignoreCase;

/**
 @brief Returns a dictionary as keys and values mapped to URL parameter names and values. Returns nil for any malformed string.
 @param urlQuery The url query string
 @return The dictionary as keys and values mapped to URL parameter names and values.
 */
+ (NSDictionary *)dictionaryWithURLQuery:(NSString *)urlQuery;

/**
 @brief return a dictionary representation of the query string from an NSURL instance. 
 @param url The url
 @returns a dictionary representation of the query string
*/
+ (NSDictionary *)queryDictionaryFromUrl:(NSURL *)url;

@end

/**
 @details Misc NSURL helper methods.
 */
@interface NSURL (CUTCategories)

/**
 @brief Create a new URL by appending a query paramter.
 @details For example, if the URL is http://www.microsoft.com/ and parameter name is p1 and value name is v1, the output of this method with be a new URL that is http://wwww.microsoft.com/?p1=v1 .
 @param paramterName The name of the parameter.
 @param value        The value of the parameter.
 @return A new NSURL object with the parameter appended.
 */
- (NSURL *)urlByAppendingQueryParameter:(NSString *)parameterName
                              withValue:(NSString *)value;

/**
 @brief Returns the absolute string with masking values of specific parameters
 @param paramsToMask The parameters to be masked from the string
 @return The absolute string with parameters masked
 */
- (NSString *)absoluteStringByMaskingValuesForParameters:(NSArray *)paramsToMask;

/**
 @brief Returns the absolute string excluding any parameters from original URL
 @return The absolute string without any parameters
 */
- (NSString *)absoluteStringExcludingParameters;

@end

/**
 @details Misc NSError helper methods.
 */
@interface NSError (CUTCategories)

/**
 @details An helper category for allocating and sending messages to NSError.
 @param domain  The error domain.
 @param code    The error code.
 @param message The error message.
 @return An NSError initialized with all the properties.
 */
+ (NSError *)errorWithDomain:(NSString *)domain code:(NSInteger)code message:(NSString *)message;

/**
 @details returns the inner error in the user info dictionary (under key NSUnderlyingErrorKey)
 */
- (NSError *)innerError;

@end

/**
 @details Misc NSThread helper methods.
 */
@interface NSThread (CUTCategories)

/**
 @details returns a regex for determining the threadId of an NSThread object.
 */
+ (NSRegularExpression *)regexForThreadId;

/**
 @details returns the thread ID as an NSString.
 */
- (NSString *)threadId;

@end

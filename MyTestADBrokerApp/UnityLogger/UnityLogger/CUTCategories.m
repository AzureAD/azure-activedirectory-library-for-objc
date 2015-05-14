/*
 Copyright © 2013 Microsoft. All rights reserved.
 
 Synopsis: Contains categories for common utility library
 
 Owner: yiweizha
 Created: 9/26/2013
 */

#import <CommonCrypto/CommonDigest.h>
#import "CUTCategories.h"

@implementation NSString (CUTCategories)

//
// containsString:
//
-(BOOL)containsString:(NSString*)substring
{
    NSRange range = [self rangeOfString : substring];
    BOOL found = ( range.location != NSNotFound );
    return found;
}

//
// containsString:ignoringCase:
//
-(BOOL)containsString:(NSString *)aString
         ignoringCase:(BOOL)ignoreCase
{
    if (aString.length == 0) { return NO; }
    
    NSRange range = [self rangeOfString:aString options:NSCaseInsensitiveSearch];
    return range.location != NSNotFound;
}

//
// hasPrefix:ignoringCase:
//
- (BOOL)hasPrefix:(NSString *)aString
     ignoringCase:(BOOL)ignoreCase
{
    if (aString == nil) return NO;
    if (aString.length > self.length) return NO;
    
    NSString *prefix = [self substringToIndex:aString.length];
    return [prefix isEqualToString:aString ignoringCase:ignoreCase];
}

//
// stringFromBool:
//
+(NSString *)stringFromBool:(BOOL)val
{
    return val ? @"YES" : @"NO";
}

//
// stringWithUnsignedInteger:
//
+ (NSString *)stringWithUnsignedInteger:(NSUInteger)value
{
    return [NSString stringWithFormat:@"%lu", (unsigned long)value];
}

//
// stringByAddingPercentEscapesIncludingAllLegalURLCharactersUsingEncoding:
//
- (NSString *)stringByAddingPercentEscapesIncludingAllLegalURLCharactersUsingEncoding:(NSStringEncoding)enc
{
    return CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(
                                                                     NULL,
                                                                     (__bridge CFStringRef)self,
                                                                     NULL,
                                                                     CFSTR("!*'();:@&=+$,/?%#[]"),
                                                                     CFStringConvertNSStringEncodingToEncoding(enc)));
}

//
// stringByReplacingPercentEscapesIncludingPlusAsASpaceUsingEncoding
//
- (NSString *)stringByReplacingPercentEscapesIncludingPlusAsASpaceUsingEncoding:(NSStringEncoding)enc
{
    return [[self stringByReplacingOccurrencesOfString:@"+" withString:@" "]
            stringByReplacingPercentEscapesUsingEncoding:enc];
}

//
// stringWithURLQueryDictionary:
//
+ (NSString *)stringWithURLQueryDictionary:(NSDictionary *)dict
{
    NSString *urlParams;
    for (NSString *key in dict)
    {
        urlParams = [NSString stringWithFormat:@"%@%@=%@",
                     (urlParams) ? [NSString stringWithFormat:@"%@&", urlParams] : @"",
                     key, // Due to odata parameters that has '$' character (Ex. $orderby), encoding this may cause problems.
                     [[dict objectForKey:key] stringByAddingPercentEscapesIncludingAllLegalURLCharactersUsingEncoding:NSUTF8StringEncoding]];
    }
    
    return urlParams;
}

//
// compareToVersion:
//
- (NSComparisonResult)compareToVersion:(NSString *)version
{
    NSArray *versionComponents1 = [self componentsSeparatedByString:@"."];
    NSArray *versionComponents2 = [version componentsSeparatedByString:@"."];
    NSInteger maxComponents = MAX([versionComponents1 count], [versionComponents2 count]);
    
    for (NSUInteger componentIndex = 0; componentIndex < maxComponents; ++componentIndex)
    {
        // If a value is missing (i.e. component 3 of 1.0, replace it with a 0 -- 1.0.0)
        NSInteger version1Component = (componentIndex < [versionComponents1 count]) ? [versionComponents1[componentIndex] integerValue] : 0;
        NSInteger version2Component = (componentIndex < [versionComponents2 count]) ? [versionComponents2[componentIndex] integerValue] : 0;
        
        if (version1Component > version2Component) return NSOrderedDescending;
        if (version1Component < version2Component) return NSOrderedAscending;
    }
    
    return NSOrderedSame;
}

//
// stringByMaskingCharacters
//
- (NSString *)stringByMaskingCharacters
{
    return [self stringByMaskingCharactersWithUnmaskedCharactersToEnd:0];
}

//
// stringByMaskingCharactersWithUnmaskedCharactersToEnd
//
- (NSString *)stringByMaskingCharactersWithUnmaskedCharactersToEnd:(NSUInteger)numberOfCharacters
{
    NSUInteger len = [self length];
    return (len > numberOfCharacters) ? [NSString stringWithFormat:@"***(%lu)%@", (unsigned long)len - numberOfCharacters, [self substringFromIndex:len - numberOfCharacters]] : self;
}

//
// isEqualToString:ignoringCase:
//
- (BOOL)isEqualToString:(NSString *)aString
           ignoringCase:(BOOL)shouldIgnoreCase
{
    if (shouldIgnoreCase)
    {
        return ([self caseInsensitiveCompare:aString] == NSOrderedSame);
    }
    return [self isEqualToString:aString];
}

//
//  isSecureURL
//
- (BOOL) isSecureURL
{
    NSURL *url = [NSURL URLWithString:self];
    
    return [url.scheme isEqualToString:@"https" ignoringCase:YES];
}

//
// containsCookieDomain
//
- (BOOL) containsCookieDomain:(NSString *)cookieDomain
{
    if (cookieDomain.length == 0)
    {
        return NO;
    }
    
    NSString *selfDomain = [NSString stringWithFormat:@".%@", self];
    
    return [selfDomain hasSuffix:cookieDomain];
}

//
// isValidGuid
//
- (BOOL) isValidGuid
{
    NSString *guidValidationRegex = @"\\A[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\\Z";
    
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:guidValidationRegex
                                                                           options:NSRegularExpressionCaseInsensitive
                                                                             error:nil];
    
    if ([regex numberOfMatchesInString:self options:0 range:NSMakeRange(0, self.length)] == 1U)
    {
        return YES;
    }
    else
    {
        return NO;
    }
}

//
// isEmptyGuid
//
- (BOOL)isEmptyGuid
{
    NSString *emptyGuid = @"00000000-0000-0000-0000-000000000000";
    NSString *emptyGuidWithBrackets = @"{00000000-0000-0000-0000-000000000000}";
    
    return [self compare:emptyGuid] == NSOrderedSame || [self compare:emptyGuidWithBrackets] == NSOrderedSame;
}

@end

@implementation NSArray (CUTCategories)

//
// firstObjectMatchingPredicate
//
- (id)firstObjectMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate
{
    CUTAssert(predicate != nil, kCUTUtilityDomain, @"Predicate should not be nil");
    
    if (predicate == nil) { return nil; }
    
    for (NSUInteger a = 0U; a < self.count; a++)
    {
        if (predicate(self[a], a))
        {
            return self[a];
        }
    }
    
    return nil;
}

//
// objectsMatchingPredicate
//
- (NSArray *)objectsMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate
{
    CUTAssert(predicate != nil, kCUTUtilityDomain, @"Predicate should not be nil");
    
    if (predicate == nil) { return nil; }
    
    NSMutableArray *result = [NSMutableArray array];
    
    for (NSUInteger a = 0U; a < self.count; a++)
    {
        if (predicate(self[a], a))
        {
            [result addObject:self[a]];
        }
    }
    
    return result;
}

//
// containsObjectMatchingPredicate:
//
- (BOOL)containsObjectMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate
{
    id objMatchingPredicate = [self firstObjectMatchingPredicate:predicate];
    return objMatchingPredicate ? YES : NO;
}

//
// arrayByMaskingStringValues:
//
- (NSArray *)arrayByMaskingStringValues
{
    NSMutableArray *maskedArray = [NSMutableArray new];
    
    for (NSString *value in self)
    {
        if ([value isKindOfClass:[NSString class]])
        {
            [maskedArray addObject:[value stringByMaskingCharacters]];
        }
    }
    
    return maskedArray;
}

@end


@implementation NSMutableArray (modifyingOrder)

//
// moveObjectAtIndex:toIndex:
//
- (void)moveObjectAtIndex:(NSUInteger)fromIndex
                  toIndex:(NSUInteger)destinationIndex
{
    if (fromIndex == destinationIndex) { return; }
    
    CUTAssert(fromIndex < self.count, kCUTUtilityDomain, @"Cannot move from index outside of array bounds.");
    CUTAssert(destinationIndex < self.count, kCUTUtilityDomain, @"Cannot move to index outside of array bounds.");
    if (fromIndex >= self.count) { return; }
    if (destinationIndex >= self.count) { return; }
    
    id sourceObject = self[fromIndex];
    [self removeObjectAtIndex:fromIndex];
    
    [self insertObject:sourceObject atIndex:destinationIndex];
}

//
// removeObjectsMatchingPredicate:
//
- (NSUInteger)removeObjectsMatchingPredicate:(BOOL (^)(id obj, NSUInteger index))predicate
{
    CUTAssert(predicate != nil, kCUTUtilityDomain, @"Condition predicate should be set.");
    if (!predicate) { return 0; }
    
    NSIndexSet *indexes = [self indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL *stop) {
        return predicate(obj, idx);
    }];
    
    if (indexes.count > 0)
    {
        [self removeObjectsAtIndexes:indexes];
    }
    
    return indexes.count;
}

//
// addObectIfNotNil:
//
- (BOOL)addObjectIfNotNil:(id)obj;
{
    if (obj != nil)
    {
        [self addObject:obj];
        return YES;
    }
    
    return NO;
}

@end


@implementation NSFileManager (fileAttributes)

//
// fileSizeInBytes:error:
//
+(NSUInteger)fileSizeInBytes:(NSString*)filePath error:(NSError **)err
{
    // get file manager
    NSFileManager *man = [NSFileManager defaultManager];
    
    // get file's attributes
    NSDictionary *fileAttributes = [man attributesOfItemAtPath:filePath error:err];
    
    // get the size attribute as NSNumber
    NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
    
    // by using unsignedIntegerValue we assume that the file size is less then 4GB
    // but that a legitimate assumption on iOS.
    NSUInteger fileSize = [fileSizeNumber unsignedIntegerValue];
    
    return fileSize;
}

//
// Get directory for cache
//
+(NSString *)cachesDirectory
{
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    
    if (paths.count > 0)
    {
        return [paths objectAtIndex:0];
    }
    
    return nil;
}

//
// Generate the full path with based directory and relative path
//
+ (NSString *)directoryWithBaseDirectory:(NSSearchPathDirectory)baseDirectory relativePath:(NSString *)relativePath
{
    NSArray *paths = NSSearchPathForDirectoriesInDomains(baseDirectory, NSUserDomainMask, YES);
    
    NSString *fullDirectory = [paths objectAtIndex:0];
    fullDirectory = [fullDirectory stringByAppendingPathComponent:relativePath];
    
    return fullDirectory;
}

@end

@implementation NSData (CUTCategories)

//
// md5
//
- (NSString*)md5
{
    unsigned char result[16];
    CC_MD5( self.bytes, (CC_LONG)self.length, result ); // This is the md5 call
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}

//
// bytesFromKilobytes:
//
+ (NSUInteger)bytesFromKilobytes:(NSUInteger)numberOfKilobytes
{
    return numberOfKilobytes * 1024;
}

@end

@implementation NSObject (CUTCategories)

//
// getNilOrValue:
//
+(id)getNilOrValue:(id)aValue
{
    if (aValue == nil || aValue == [NSNull null])
    {
        return nil;
    }
    return aValue;
}

//
// getNilOrValue:
//
+(id)getNSNullOrValue:(id)aValue
{
    if (aValue == nil || aValue == [NSNull null])
    {
        return [NSNull null];
    }
    
    return aValue;
}

@end

@implementation NSDate(CUTCategories)

//
// utcDateFromString:
//
+ (NSDate *)utcDateFromString:(NSString *)string
{
    // Add all supported formats here.
    NSArray *utcDateFormats = @[@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
                                @"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    NSDate *utcDate = nil;
    
    for (NSString *format in utcDateFormats)
    {
        utcDate = [[self class] utcDateFromString:string withFormat:format];
        if (utcDate != nil)
        {
            break;
        }
    }
    
    if (utcDate == nil)
    {
        CUTTrace(CUTTraceLevelInfo, kCUTUtilityDomain, @"Failed to convert the string:%@ to UTC date", string);
    }
    
    return utcDate;
}

//
// utcDateFromString:withFormat:
//
+ (NSDate *) utcDateFromString:(NSString *)string
                    withFormat:(NSString *)format
{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    NSLocale *locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    [formatter setLocale:locale];
    [formatter setDateFormat:format];
    [formatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    return [formatter dateFromString:string];
}

//
// stringFromUtcDate:withFormat:
//
+ (NSString *)stringFromUtcDate:(NSDate *)date
                     withFormat:(NSString *)format
{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    [formatter setDateFormat:format];
    return [formatter stringFromDate:date];
}

@end

@implementation NSDictionary (CUTCategories)

//
// queryDictionaryFromUrl:
//
+ (NSDictionary *)queryDictionaryFromUrl:(NSURL *)url
{
    // NSURL exposes the property query, however, this property doesn't work if the scheme doesn't followed by 2 backsleshes.
    // Therefore adding code that returns the query string even if the URL has this format [scheme]:?[query]
    // (and not just [scheme]://?[query])
    NSString *absoluteString = [url absoluteString];
    NSRange questionMarkLocation = [absoluteString rangeOfString:@"?"];
    if (questionMarkLocation.length == 0)
    {
        return  nil;
    }
    
    // get the string after the question mark
    NSString *query = [absoluteString substringFromIndex:questionMarkLocation.location + 1];
    
    // return the query string as a dictionary
    return [NSDictionary dictionaryWithURLQuery:query];
}

//
// dictionaryWithURLQuery:
//
+ (NSDictionary *)dictionaryWithURLQuery:(NSString *)urlQuery
{
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    NSArray *queryParameters = [urlQuery componentsSeparatedByString:@"&"];
    for (NSString *param in queryParameters)
    {
        NSArray *keyValue = [param componentsSeparatedByString:@"="];
        
        if (keyValue.count != 2U)
        {
            return nil;
        }
        
        [dict setObject:keyValue[1] forKey:keyValue[0]];
    }
    
    return (dict.count > 0) ? dict : nil;
}

//
// objectForKey:ofClass:
//
- (id)objectForKey:(id)aKey ofClass:(Class) aClass;
{
    id value = self[aKey];
    if ([value isKindOfClass:aClass])
    {
        return value;
    }
    return nil;
}

//
// objectForKey:withDefault:keyExists:
//
- (id)objectForKey:(id)aKey withDefault:(id)defaultValue keyExists:(BOOL *)keyExists
{
    BOOL exists = YES;
    id tmpValue = [self objectForKey:aKey];
    
    if (! tmpValue)
    {
        exists = NO;
        tmpValue = defaultValue;
    }
    else if (tmpValue == [NSNull null])
    {
        exists = YES;
        tmpValue = nil;
    }
    
    if (nil != keyExists)
    {
        *keyExists = exists;
    }
    
    if (!exists)
    {
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"Key \"%@\" did not exist, defaulting to %@", aKey, defaultValue);
    }
    
    return tmpValue;
}

//
// objectForStringKey:ignoringCase:
//
- (id)objectForStringKey:(NSString *)key
            ignoringCase:(BOOL)ignoreCase
{
    if (!ignoreCase)
    {
        return [self objectForKey:key];
    }
    
    for (id dictKey in [self allKeys])
    {
        if ([dictKey isKindOfClass:[NSString class]] &&
            [dictKey isEqualToString:key ignoringCase:ignoreCase])
        {
            return [self objectForKey:dictKey];
        }
    }
    return nil;
}

@end


@implementation NSURL (CUTCategories)

//
// urlByAppendingQueryParameter:withValue:
//
- (NSURL *)urlByAppendingQueryParameter:(NSString *)parameterName
                              withValue:(NSString *)value
{
    // Start with the current string.
    NSMutableString *newUrlString = [[NSMutableString alloc] init];
    [newUrlString appendString:self.absoluteString];
    
    // If there is no query, self.query = nil. Replace with an empty string.
    NSString *originalParameters = (self.query) ? self.query : [NSString string];
    
    // If there are already parameters, use &, otherwise start with ?
    NSString *separator = (originalParameters.length > 0) ? @"&" : @"?";
    if ([newUrlString hasSuffix:separator])
    {
        // It is valid for a URL to end with a separator, so skip duplicating.
        separator = [NSString string];
    }
    NSString *newParameters = [NSString stringWithFormat:@"%@%@=%@", separator, parameterName, value];
    
    // Add the new paramters to the URL
    [newUrlString appendString:newParameters];
    
    return [NSURL URLWithString:newUrlString];
}

//
//  absoluteStringByMaskingValuesForParameters
//
- (NSString *)absoluteStringByMaskingValuesForParameters:(NSArray *)paramsToMask
{
    NSString *absoluteStringByMaskingValues = [self absoluteString];
    if (absoluteStringByMaskingValues.length <= 0)
    {
        return absoluteStringByMaskingValues;
    }
    
    for (NSString *param in paramsToMask)
    {
        NSString *pattern = [NSString stringWithFormat:@"[\?&]%@=([^&]*)", param];
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                               options:0
                                                                                 error:nil];
        
        NSTextCheckingResult *match = [regex firstMatchInString:absoluteStringByMaskingValues options:0 range:NSMakeRange(0, absoluteStringByMaskingValues.length)];
        if (match && NSNotFound != match.range.location)
        {
            NSString *maskedSubString = [absoluteStringByMaskingValues substringWithRange:[match rangeAtIndex:1]];
            absoluteStringByMaskingValues = [absoluteStringByMaskingValues stringByReplacingCharactersInRange:[match rangeAtIndex:1] withString:[maskedSubString stringByMaskingCharacters]];
        }
    }
    
    return absoluteStringByMaskingValues;
}

//
//  absoluteStringExcludingParameters
//
- (NSString *)absoluteStringExcludingParameters
{
    if (self.absoluteString.length == 0)
    {
        return self.absoluteString;
    }
    
    NSString *absoluteStringExcludingParams = self.absoluteString;
    
    NSString *pattern = @"^(.*)[\?]";
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                           options:0
                                                                             error:nil];
    
    NSTextCheckingResult *match = [regex firstMatchInString:absoluteStringExcludingParams options:0 range:NSMakeRange(0, absoluteStringExcludingParams.length)];
    
    if (match && NSNotFound != match.range.location)
    {
        absoluteStringExcludingParams = [absoluteStringExcludingParams substringWithRange:[match rangeAtIndex:1]];
    }
    
    return absoluteStringExcludingParams;
}

@end

/**
 @details Misc NSError helper methods.
 */
@implementation NSError (CUTCategories)

//
// errorWithErrorCode:domain:message:
//
+ (NSError *)errorWithDomain:(NSString *)domain code:(NSInteger)code message:(NSString *)message
{
    return [NSError errorWithDomain:domain
                        code:code
                    userInfo:(message) ? @{NSLocalizedDescriptionKey: message}: nil];
}

//
// innerError
//
- (NSError *)innerError
{
    NSError *innerError = [self.userInfo objectForKey:NSUnderlyingErrorKey];
    return innerError;
}

@end

/**
 @details Misc NSThread helper methods.
 *NOTE: DO NOT Use CUTTrace in these methods, as it will cause a stack overflow.*
 */
@implementation NSThread (CUTCategories)

//
// regexForThreadId
//
+ (NSRegularExpression *)regexForThreadId
{
    static NSRegularExpression *regex;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        regex = [NSRegularExpression regularExpressionWithPattern:@"(?:num|number) = (\\d{1,})"
                                                          options:NSRegularExpressionCaseInsensitive
                                                            error:nil];
    });
    return regex;
}

//
// threadId
//
- (NSString *)threadId
{
    NSString *threadDescription = [NSString stringWithFormat:@"%@", self];
    
    // Create the expected NSThread description prefix for this particular object.
    // We assume the description will look something like:
    //    "<NSThread: 0xdeadbeef>{key1=value1, key2=value2}"
    // based on the examples below:
    //    iOS 7.1 iPhone 4s: <NSThread: 0x7a7779f0>{name = (null), num = 1}
    //    iOS 7.1 iPad Air:  <NSThread: 0x7fb24051b570>{name = (null), num = 1}
    //    iOS 8.1 iPhone 4s: <NSThread: 0x7af6f960>{number = 1, name = main}
    //    iOS 8.1 iPad Air:  <NSThread: 0x7f8fc3f18580>{number = 1, name = main}
    //    iOS 8.1 iPhone 6:  <NSThread: 0x7f9351f0b010>{number = 1, name = main}
    NSString *threadDescriptionPrefix = [NSString stringWithFormat:@"<%@: %p>", self.class, self];
    if ([threadDescription hasPrefix:threadDescriptionPrefix ignoringCase:YES])
    {
        // Make sure the description body is also what we expect, by ensuring the first and last characters are the opening
        // and closing curly braces.
        NSString *threadDescriptionBody = [threadDescription substringFromIndex:threadDescriptionPrefix.length];
        if ([threadDescriptionBody hasPrefix:@"{"] && [threadDescriptionBody hasSuffix:@"}"])
        {
            NSRegularExpression *regex = [NSThread regexForThreadId];
            NSTextCheckingResult *match = [regex firstMatchInString:threadDescriptionBody options:0 range:NSMakeRange(0, threadDescriptionBody.length)];
            if (match.numberOfRanges == 2)
            {
                // The range at index 1 returns the capture group for threadId.
                return [threadDescriptionBody substringWithRange:[match rangeAtIndex:1]];
            }
            
            // Default to returning the description body if no thread id number is found.
            return threadDescriptionBody;
        }
    }
    
    // Default to returning the entire description rather than nothing at all.
    return threadDescription;
}

@end

// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADTestLoader.h"
#import "ADTokenCacheItem.h"

#define THROW_EXCEPTION_NOLINE(INFO, FMT, ...) @throw [NSException exceptionWithName:ADTestLoaderException reason:[NSString stringWithFormat:FMT, ##__VA_ARGS__] userInfo:INFO];

#define CHECK_THROW_EXCEPTION_NOLINE(CHECK, INFO, FMT, ...) if (!CHECK) { THROW_EXCEPTION_NOLINE(INFO, FMT, ##__VA_ARGS__ ) }

#define THROW_EXCEPTION(INFO, FMT, ...) @throw [NSException exceptionWithName:ADTestLoaderException reason:[NSString stringWithFormat:FMT " (%@:%ld)", ##__VA_ARGS__, _parserPath.lastPathComponent, (long)_parser.lineNumber] userInfo:INFO];

#define CHECK_THROW_EXCEPTION(CHECK, INFO, FMT, ...) if (!CHECK) { THROW_EXCEPTION(INFO, FMT, ##__VA_ARGS__ ) }

NSExceptionName ADTestLoaderException = @"ADTestLoaderException";
NSErrorDomain ADTestErrorDomain = @"ADTestErrorDomain";

typedef enum ADTestLoaderParserState
{
    // These two states are effectively identical, the parser moves to the "parsing" state after
    // finishing with a known element
    Started,
    Parsing,
    
    // Currently parsing the TestVariables element
    TestVariables,
    TestVariableJwt,
    
    // Currently parsing the Network element
    Network,
    NetworkRequest,
    NetworkResponse,
    
    // Curently parsing the cache element
    Cache,
    
    // Parser completed
    Finished,
} ADTestLoaderParserState;

@interface ADTestLoader () <NSXMLParserDelegate>

@end

@implementation ADTestLoader
{
    NSXMLParser *_parser;
    NSString *_parserPath;
    NSMutableArray *_parserStack;
    NSMutableArray *_parserPathStack;
    
    NSUInteger _currentLevel;
    
    ADTestLoaderParserState _state;
    BOOL _captureText;
    
    // Dictionary Capture State
    NSMutableArray *_keyStack;
    NSMutableArray *_valueStack;
    
    NSString *_currentKey;
    NSMutableDictionary *_currentDict;
    NSMutableString *_currentValue;
    
    // JWT Capture State
    NSMutableArray *_jwtParts;
    
    // Token Cache Capture
    ADTokenCacheItem *_currentCacheItem;
    
    NSMutableDictionary *_testVariables;
    NSMutableArray *_networkRequests;
    NSMutableArray *_cacheItems;
}

+ (ADTestVariables *)loadTest:(NSString *)testName
{
    NSURL *testDataPath = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:testName ofType:@"xml"]];
    NSAssert(testDataPath, @"Could not create test data path URL");
    return nil;
}

+ (NSString *)pathForFile:(NSString *)fileName
{
    NSString *resource = fileName.lastPathComponent.stringByDeletingPathExtension;
    NSString *extension = fileName.pathExtension;
    if ([NSString adIsStringNilOrBlank:extension])
    {
        extension = @"xml";
    }
    
    return [[NSBundle bundleForClass:[self class]] pathForResource:resource ofType:extension];
}

- (id)initWithFile:(NSString *)file
{
    CHECK_THROW_EXCEPTION_NOLINE(file, nil, @"File must be specified");
    if (!file)
    {
        return nil;
    }
    
    NSString *filePath = [[self class] pathForFile:file];
    CHECK_THROW_EXCEPTION_NOLINE(filePath, @{ @"file" : file }, @"Could not find file \"%@\" in bundle.", file);
    
    if (!(self = [self initWithContentsOfPath:filePath]))
    {
        THROW_EXCEPTION_NOLINE(nil, @"Unable to instantiate parser");
        return nil;
    }
    
    return self;
}

- (id)initWithString:(NSString *)string
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _parser = [[NSXMLParser alloc] initWithData:[string dataUsingEncoding:NSUTF8StringEncoding]];
    _parser.delegate = self;
    _parserPath = @"string";
    
    return self;
}

- (id)initWithContentsOfPath:(NSString *)path
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _parser = [[NSXMLParser alloc] initWithStream:[NSInputStream inputStreamWithFileAtPath:path]];
    _parser.delegate = self;
    _parserPath = path;
    
    return self;
}

- (BOOL)parse:(NSError * __autoreleasing *)error
{
    _state = Started;
    _parserStack = [NSMutableArray new];
    _parserPathStack = [NSMutableArray new];
    
    BOOL ret = NO;
    // NSXMLParser is one of the few (only?) ObjC APIs that use exceptions, so to safely use this
    // parser we have to wrap the parser call in a try/catch block, and marshal out the exception as
    // an error.
    @try
    {
        ret = [_parser parse];
        if (ret == NO && error)
        {
            *error = _parser.parserError;
            
            _testVariables = nil;
            _cacheItems = nil;
            _networkRequests = nil;
        }

    }
    @catch (NSException *exception)
    {
        _testVariables = nil;
        _cacheItems = nil;
        _networkRequests = nil;
        
        if (error)
        {
            *error = [NSError errorWithDomain:ADTestErrorDomain code:-1 userInfo:@{ @"exception" : exception }];
        }
        
        return NO;
    }
    @finally
    {
        _parser = nil;
        _parserPath = nil;
        _parserPathStack = nil;
        _parserStack = nil;
    }
    
    return ret;
}

#pragma mark -
#pragma mark NSXMLParserDelegate

// sent when the parser begins parsing of the document.
- (void)parserDidStartDocument:(NSXMLParser *)parser
{
    (void)parser;
}

// sent when the parser has completed parsing. If this is encountered, the parse was successful.
- (void)parserDidEndDocument:(NSXMLParser *)parser
{
    (void)parser;
    
    if (_parserStack.count > 0)
    {
        _parser = _parserStack.lastObject;
        [_parserStack removeLastObject];
        
        _parserPath = _parserPathStack.lastObject;
        [_parserPathStack removeLastObject];
    }
    else
    {
        _state = Finished;
    }
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string
{
    (void)parser;
    if (!_captureText)
    {
        return;
    }
    
    NSString *trimmedString = [string stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!_currentValue)
    {
        _currentValue = [trimmedString mutableCopy];
    }
    else
    {
        [_currentValue appendString:trimmedString];
    }
}

- (void)startElement:(NSString *)elementName namespaceURI:(nullable NSString *)namespaceURI qualifiedName:(nullable NSString *)qName attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)namespaceURI;
    (void)qName;
    
    if ([elementName isEqualToString:@"testvariables"])
    {
        _state = TestVariables;
        [self startTestVariables:attributeDict];
        return;
    }
    
    if ([elementName isEqualToString:@"network"])
    {
        _state = Network;
        [self startNetwork:attributeDict];
        return;
    }
    else if ([elementName isEqualToString:@"cache"])
    {
        _state = Cache;
        [self startCache:attributeDict];
        return;
    }
    else
    {
        THROW_EXCEPTION(nil, @"Do not recogonized element \"%@\"", elementName);
    }
}

// sent when the parser finds an element start tag.
// In the case of the cvslog tag, the following is what the delegate receives:
//   elementName == cvslog, namespaceURI == http://xml.apple.com/cvslog, qualifiedName == cvslog
// In the case of the radar tag, the following is what's passed in:
//    elementName == radar, namespaceURI == http://xml.apple.com/radar, qualifiedName == radar:radar
// If namespace processing >isn't< on, the xmlns:radar="http://xml.apple.com/radar" is returned as an attribute pair, the elementName is 'radar:radar' and there is no qualifiedName.

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(nullable NSString *)namespaceURI qualifiedName:(nullable NSString *)qName attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)parser;
    
    elementName = elementName.lowercaseString;
    
    // Include elements are special...
    if ([elementName isEqualToString:@"include"])
    {
        NSString *file = attributeDict[@"file"];
        CHECK_THROW_EXCEPTION(file, nil, @"File not specified in include tag.");
        
        NSString *filePath = [[self class] pathForFile:file];
        CHECK_THROW_EXCEPTION(filePath, @{ @"file" : file }, @"Unable to find file %@", file);
        
        [_parserStack addObject:_parser];
        [_parserPathStack addObject:_parserPath];
        
        _parser = [[NSXMLParser alloc] initWithStream:[NSInputStream inputStreamWithFileAtPath:filePath]];
        _parser.delegate = self;
        _parserPath = filePath;
        
        __block NSException *thrownException = nil;
        dispatch_queue_t reentrantAvoidanceQueue = dispatch_queue_create("reentrantAvoidanceQueue", DISPATCH_QUEUE_SERIAL);
        dispatch_async(reentrantAvoidanceQueue, ^{
            @try
            {
                [_parser parse];
            }
            @catch (NSException *exception)
            {
                thrownException = exception;
            }
        });
        dispatch_sync(reentrantAvoidanceQueue, ^{});
        
        if (thrownException)
        {
            @throw thrownException;
        }
        
        return;
    }
    
    switch (_state)
    {
        case Started:
        case Parsing:
            [self startElement:elementName namespaceURI:namespaceURI qualifiedName:qName attributes:attributeDict];
            return;
        case TestVariables:
            [self parseTestVariables:elementName attributes:attributeDict];
            return;
        case TestVariableJwt:
            [self parseJwt:elementName attributes:attributeDict];
            return;
        case Network:
        case NetworkRequest:
        case NetworkResponse:
            [self parseNetwork:elementName attributes:attributeDict];
            return;
        case Cache:
            [self parseCache:elementName attributes:attributeDict];
            return;
        case Finished:
            THROW_EXCEPTION(nil, @"Parser encountered element after finished parsing.");
    }
}

// sent when an end tag is encountered. The various parameters are supplied as above.
- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(nullable NSString *)namespaceURI qualifiedName:(nullable NSString *)qName
{
    (void)parser;
    (void)namespaceURI;
    (void)qName;
    
    elementName = elementName.lowercaseString;
    
    if ([elementName isEqualToString:@"include"])
    {
        return;
    }
    
    switch (_state)
    {
        case Started:
        case Parsing:
            THROW_EXCEPTION(nil, @"End element before start element.");
            return;
        case TestVariables:
            [self endTestVariables:elementName];
            return;
        case TestVariableJwt:
            [self endJwt:elementName];
            return;
        case Network:
        case NetworkRequest:
        case NetworkResponse:
            [self endNetwork:elementName];
            return;
        case Cache:
            [self endCache:elementName];
            return;
        case Finished:
            THROW_EXCEPTION(nil, @"Parser encountered element after finished parsing.");
    }
}

#pragma mark -
#pragma mark Dictionary Capturing

- (void)startDictionaryCapture:(NSString *)startingKey
{
    _keyStack = [NSMutableArray new];
    _valueStack = [NSMutableArray new];
    _currentDict = [NSMutableDictionary new];
    _currentKey = startingKey;
}

- (void)startElement:(NSString *)name
{
    _captureText = YES;
    [_keyStack addObject:_currentKey];
    if (!_currentDict)
    {
        _currentDict = [NSMutableDictionary new];
        [_valueStack.lastObject setValue:_currentDict forKey:_currentKey];
    }
    [_valueStack addObject:_currentDict];
    _currentDict = nil;
    _currentKey = name;
}

- (BOOL)endElement:(NSString *)name
{
    NSAssert([name isEqualToString:_currentKey], @"mismatched end tag");
    _captureText = NO;
    
    NSMutableDictionary *parentDict = _valueStack.lastObject;
    if (!parentDict)
    {
        return NO;
    }
    
    if (_currentValue.length > 0)
    {
        [parentDict setValue:[_currentValue copy] forKey:name];
        [_currentValue setString:@""];
    }
    
    _currentKey = [_keyStack lastObject];
    [_keyStack removeLastObject];
    
    _currentDict = parentDict;
    [_valueStack removeLastObject];
    
    return YES;
}


#pragma mark -
#pragma mark Test Variables

- (void)startTestVariables:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)attributeDict;
    
    CHECK_THROW_EXCEPTION(!_testVariables, nil, @"Multiple TestVariables dictionaries in test file");
    
    [self startDictionaryCapture:@"testvariables"];
    _testVariables = _currentDict;
}

- (void)parseTestVariables:(NSString *)elementName
                attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    [self startElement:elementName];
    NSString *type = attributeDict[@"type"];
    if ([type isEqualToString:@"jwt"])
    {
        _state = TestVariableJwt;
        _jwtParts = [NSMutableArray new];
    }
}

- (void)endTestVariables:(NSString *)elementName
{
    if (![self endElement:elementName])
    {
        _state = Parsing;
        _testVariables = _currentDict;
    }
}

#pragma mark JWT

- (void)parseJwt:(NSString *)elementName
      attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)attributeDict;
    
    CHECK_THROW_EXCEPTION([elementName isEqualToString:@"part"], nil, @"Unsupported element type \"%@\", only \"part\" is supporting in JWT parsing.", elementName);
}

- (void)endJwt:(NSString *)elementName
{
    if ([elementName isEqualToString:@"part"])
    {
        NSString *base64Json = [_currentValue adBase64UrlEncode];
        [_jwtParts addObject:base64Json];
        [_currentValue setString:@""];
    }
    else if ([elementName isEqualToString:_currentKey])
    {
        NSString *format = @"%@";
        for (NSString *part in _jwtParts)
        {
            [_currentValue appendFormat:format, part];
            format = @".%@";
        }
        
        [self endElement:elementName];
        _state = TestVariables;
    }
}

#pragma mark -
#pragma mark Network

- (void)startNetwork:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)attributeDict;
}

- (void)parseNetwork:(NSString *)elementName
          attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)elementName;
    (void)attributeDict;
}

- (void)endNetwork:(NSString *)elementName
{
    (void)elementName;
}

#pragma mark -
#pragma mark Cache

- (void)startCache:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    (void)attributeDict;
    _cacheItems = [NSMutableArray new];
}

- (void)parseCache:(NSString *)elementName
        attributes:(NSDictionary<NSString *, NSString *> *)attributeDict
{
    _currentCacheItem = [ADTokenCacheItem new];
    
    (void)elementName;
    (void)attributeDict;
}

- (void)endCache:(NSString *)elementName
{
    (void)elementName;
}


@end

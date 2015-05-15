/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: This class parse the IW ServCUT JSON responses.
 
 Owner: IndikaK
 Created: 02/20/2013
 */

#import "CUTJsonParser.h"

@interface CUTJsonParser()

@property (nonatomic, strong) Class entityType;
@property (nonatomic, assign) BOOL isACollection;
@property (nonatomic, assign) BOOL isSimpleJsonParser;

@end

@implementation CUTJsonParser

- (id)initWithEntityType:(Class)entityType forSimpleJson:(BOOL)isForSimpleJson forACollection:(BOOL)isACollection
{
    if (!(self = [super init])) { return  nil; };
    
    _entityType = entityType;
    _isACollection = isACollection;
    _isSimpleJsonParser = isForSimpleJson;
    
    return self;
}

+ (id)topLevelObjectByParsingData:(NSData *)data
                          forType:(Class)aType
                            error:(NSError **)error
{
    if (!error)
    {
        CUTAssert(error != nil, kCUTUtilityDomain, @"error parameter is nil");
        return nil;
    }
    *error = nil;
    
    NSError *jsonError = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
    
    if (jsonError != nil)
    {
        *error = jsonError;
        return nil;
    }
    
    // If the type is spceified, validate for the type.
    if (aType && ![jsonObject isKindOfClass:aType])
    {
        *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTHttpErrorInvalidServiceResponse userInfo:nil];
        return nil;
    }
    
    return jsonObject;
}

#pragma mark - CUTHttpConnectorParserDelegate

/**
 @brief This method parse the JSON data, as simple JSON or oData as per how the parser was initialized,
 @details If this is created as a collection parser, the response is parsed as a collection of entity provided during the creation. Otherwise it will parse the response to the entity type.
 @param data   Data to parse.
 @param error  Out put error parameter to set during any error.
 */
- (id)parseData:(NSData *)data
          error:(NSError **)error
{
    if (!error)
    {
        CUTAssert(error != nil, kCUTUtilityDomain, @"error parameter is nil");
        return nil;
    }
    
    // First level of the response must be a NSDictionary for an oData response. For simple Json data, it can be NSDictionary or NSArray.
    id jsonObject = [CUTJsonParser topLevelObjectByParsingData:data
                                                       forType:(self.isSimpleJsonParser) ? nil : [NSDictionary class]
                                                         error:error];
    if (*error != nil)
    {
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain,
                 @"Error in JSON serialization: %@", *error);
        
        return nil;
    }
    
    if (!self.isACollection)
    {
        // Parse the response to the given entity.
        id entity = [[self.entityType alloc] initWithDictionary:jsonObject];
        if (entity == nil)
        {
            CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain,
                     @"Invalid JSON response.");
            
            *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTHttpErrorInvalidServiceResponse userInfo:nil];
            return nil;
        }
        
        *error = nil;
        return entity;
    }
    
    // Parse the response as a collection of the given entity.
    // For collections, oData full-metadata response has the following format:
    /*
     {
     "odata.metadata":"http://....."
     "value":"inner object"
     */
    // For simple JSON responses, the format is any dictionary or array.
    
    
    id arryOfObjects = self.isSimpleJsonParser ? jsonObject : jsonObject[@"value"];
    if (arryOfObjects == nil)
    {
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain,
                 @"Invalid JSON response. The value field does not contain data.");
        
        *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTHttpErrorInvalidServiceResponse userInfo:nil];
        return nil;
    }
    
    NSMutableArray *collection = [[NSMutableArray alloc] init];
    for (id entry in arryOfObjects)
    {
        if (![entry isKindOfClass:[NSDictionary class]])
        {
            CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain,
                     @"Invalid IW ServCUT JSON response. Expected NSDictionary, but received %@",  NSStringFromClass([entry class]));
            
            *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTHttpErrorInvalidServiceResponse userInfo:nil];
            return nil;
        }
        
        id entity = [[self.entityType alloc] initWithDictionary:entry];
        if (entity == nil)
        {
            CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain,
                     @"Invalid IW ServCUT JSON response. Child entity is nil");
            
            *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTHttpErrorInvalidServiceResponse userInfo:nil];
            return nil;
        }
        
        [collection addObject:entity];
    }
    
    *error = nil;
    return collection;
}

@end

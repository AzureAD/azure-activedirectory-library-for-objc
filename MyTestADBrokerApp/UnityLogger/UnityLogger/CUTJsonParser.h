/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: This class parse the IW Service JSON responses.
 
 Owner: IndikaK
 Created: 02/20/2013
 */

#import <Foundation/Foundation.h>
#import "CUTHttpConnector.h"

@interface CUTJsonParser : NSObject <CUTHttpConnectorParserDelegate>

/**
 @brief This method parse the JSON data, and retuns the top level object.
 @param data   Data to parse.
 @param aType  Optionla parameter to specify the type of the top level object. Specify nil to avoid any type checking.
 @param error  Output error parameter to set during any error. This must be not nil.
 */
+ (id)topLevelObjectByParsingData:(NSData *)data
                          forType:(Class)aType
                            error:(NSError **)error;

/**
 @brief Initializes a JSON parser for deserializing data that is in oData JSON format to a CUTDictionaryBasedEntity subclass.
 @param entityType The type of the CUTDictionaryBasedEntity subclass expected for the parser to deserialize data.
 @param isSimpleJson If YES initializes the instance to parses simple JSON and if NO, initializes the instance to parse full-metadata oData.
 @param isACollection Identifies if the parser is looking for an array of objects (of type entityType) in the oData data.
 */
- (id)initWithEntityType:(Class)entityType
           forSimpleJson:(BOOL)isForSimpleJson
          forACollection:(BOOL)isACollection;

@end

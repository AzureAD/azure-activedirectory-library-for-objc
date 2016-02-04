// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

//iOS does not support resources in client libraries. Hence putting the
//version in static define until we identify a better place:
#define ADAL_VER_HIGH       2
#define ADAL_VER_LOW        1
#define ADAL_VER_PATCH      0

#define STR_ADAL_VER_HIGH   "2"
#define STR_ADAL_VER_LOW    "1"
#define STR_ADAL_VER_PATCH  "0"

// Framework versions only support high and low for the double value, sadly.
#define ADAL_VERSION_NUMBER 2.1

#define ADAL_VERSION_STRING     STR_ADAL_VER_HIGH "." STR_ADAL_VER_LOW "." STR_ADAL_VER_PATCH "-beta.1"
#define ADAL_VERSION_NSSTRING   @"" STR_ADAL_VER_HIGH "." STR_ADAL_VER_LOW "." STR_ADAL_VER_PATCH "-beta.1"

#import "ADLogger+Internal.h"
#import "ADErrorCodes.h"
#import "ADAuthenticationError.h"
#import "NSString+ADHelperMethods.h"

@class ADAuthenticationResult;

/*! The completion block declaration. */
typedef void(^ADAuthenticationCallback)(ADAuthenticationResult* result);

#if TARGET_OS_IPHONE
//iOS:
#   include <UIKit/UIKit.h>
typedef UIWebView WebViewType;
#else
//OS X:
#   include <WebKit/WebKit.h>
typedef WebView   WebViewType;
#endif


//Helper macro to initialize a variable named __where string with place in file details:
#define WHERE \
NSString* __where = [NSString stringWithFormat:@"In function: %s, file line #%u", __PRETTY_FUNCTION__, __LINE__]

#define ADAL_VERSION \
NSString* __adalVersion = [NSString stringWithFormat:@"ADAL API call [Version - %@]",[ADLogger getAdalVersion]]

//General macro for throwing exception named NSInvalidArgumentException
#define THROW_ON_CONDITION_ARGUMENT(CONDITION, ARG) \
{ \
    if (CONDITION) \
    { \
        WHERE; \
        AD_LOG_ERROR(@"InvalidArgumentException: " #ARG, AD_ERROR_INVALID_ARGUMENT, nil, __where); \
        @throw [NSException exceptionWithName: NSInvalidArgumentException \
                                       reason:@"Please provide a valid '" #ARG "' parameter." \
                                     userInfo:nil];  \
    } \
}

// Checks a selector NSString argument to a method for being null or empty. Throws NSException with name
// NSInvalidArgumentException if the argument is invalid:
#define THROW_ON_NIL_EMPTY_ARGUMENT(ARG) THROW_ON_CONDITION_ARGUMENT([NSString adIsStringNilOrBlank:ARG], ARG);

//Checks a selector argument for being null. Throws NSException with name NSInvalidArgumentException if
//the argument is invalid
#define THROW_ON_NIL_ARGUMENT(ARG) THROW_ON_CONDITION_ARGUMENT(!(ARG), ARG);

//Added to methods that are not implemented yet:
#define NOT_IMPLEMENTED @throw [NSException exceptionWithName:@"NotImplementedException" reason:@"Not Implemented" userInfo:nil];

//Fills the 'error' parameter
#define FILL_PARAMETER_ERROR(ARG) \
if (error) \
{ \
*error = [ADAuthenticationError errorFromArgument:ARG \
argumentName:@#ARG]; \
}

#define STRING_NIL_OR_EMPTY_CONDITION(ARG) [NSString adIsStringNilOrBlank:ARG]
#define NIL_CONDITION(ARG) (!ARG)

#define RETURN_ON_INVALID_ARGUMENT(CONDITION, ARG, RET) \
{ \
    if (CONDITION) \
    { \
        WHERE; \
        AD_LOG_ERROR(@"InvalidArgumentError: " #ARG, AD_ERROR_INVALID_ARGUMENT, nil, __where); \
        FILL_PARAMETER_ERROR(ARG); \
        return RET; \
    } \
}

//Used for methods that have (ADAuthenticationError * __autoreleasing *) error parameter to be
//used for error conditions. The macro checks if ARG is nil or an empty string, sets the error and returns nil.
#define RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(ARG) RETURN_ON_INVALID_ARGUMENT(STRING_NIL_OR_EMPTY_CONDITION(ARG), ARG, nil)

//Used for methods that have (ADAuthenticationError * __autoreleasing *) error parameter to be
//used for error conditions, but return no value (void). The macro checks if ARG is nil or an empty string,
//sets the error and returns.
#define RETURN_ON_NIL_EMPTY_ARGUMENT(ARG) RETURN_ON_INVALID_ARGUMENT(STRING_NIL_OR_EMPTY_CONDITION(ARG), ARG, )

//Same as the macros above, but used for non-string parameters for nil checking.
#define RETURN_NIL_ON_NIL_ARGUMENT(ARG) RETURN_ON_INVALID_ARGUMENT(NIL_CONDITION(ARG), ARG, nil)

//Same as the macros above, but returns BOOL (NO), instead of nil.
#define RETURN_NO_ON_NIL_ARGUMENT(ARG) RETURN_ON_INVALID_ARGUMENT(NIL_CONDITION(ARG), ARG, NO)

//Same as the macros above, but used for non-string parameters for nil checking.
#define RETURN_ON_NIL_ARGUMENT(ARG) RETURN_ON_INVALID_ARGUMENT(NIL_CONDITION(ARG), ARG, )

//Converts constant string literal to NSString. To be used in macros, e.g. TO_NSSTRING(__FILE__).
//Can be used only inside another macro.
#define TO_NSSTRING(x) @"" x

//Logs public function call:
#define API_ENTRY \
{ \
WHERE; \
ADAL_VERSION; \
AD_LOG_VERBOSE(__adalVersion, nil, __where); \
}

#if __has_feature(objc_arc)
#   define SAFE_ARC_PROP_RETAIN strong
#   define SAFE_ARC_RETAIN(x) (x)
#   define SAFE_ARC_RELEASE(x) x = nil;
#   define SAFE_ARC_AUTORELEASE(x) (x)
#   define SAFE_ARC_BLOCK_COPY(x) (x)
#   define SAFE_ARC_BLOCK_RELEASE(x)
#   define SAFE_ARC_SUPER_DEALLOC()
#   define SAFE_ARC_AUTORELEASE_POOL_START() @autoreleasepool {
#   define SAFE_ARC_AUTORELEASE_POOL_END() }
#   define SAFE_ARC_DISPATCH_RETAIN(x)
#   define SAFE_ARC_DISPATCH_RELEASE(x)
#else
#   define SAFE_ARC_PROP_RETAIN retain
#   define SAFE_ARC_RETAIN(x) ([(x) retain])
#   define SAFE_ARC_RELEASE(x) { [(x) release]; x=nil; }
#   define SAFE_ARC_AUTORELEASE(x) ([(x) autorelease])
#   define SAFE_ARC_BLOCK_COPY(x) (Block_copy(x))
#   define SAFE_ARC_BLOCK_RELEASE(x) (Block_release(x))
#   define SAFE_ARC_SUPER_DEALLOC() ([super dealloc])
#   define SAFE_ARC_AUTORELEASE_POOL_START() NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
#   define SAFE_ARC_AUTORELEASE_POOL_END() [pool release];
#   define SAFE_ARC_DISPATCH_RETAIN(x) dispatch_retain((x))
#   define SAFE_ARC_DISPATCH_RELEASE(x) dispatch_release((x))
#endif

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

// iOS does not support resources in client libraries. Hence putting the
// version in static define until we identify a better place.
// (Note: All Info.plist files read version numbers from the following three lines
// through build script. Don't change its format unless changing build script as well.)
#define ADAL_VER_HIGH       2
#define ADAL_VER_LOW        6
#define ADAL_VER_PATCH      3

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define INT_CONCAT_HELPER(x,y) x ## . ## y
#define INT_CONCAT(x,y) INT_CONCAT_HELPER(x,y)

// Framework versions only support high and low for the double value, sadly.
#define ADAL_VERSION_NUMBER INT_CONCAT(ADAL_VER_HIGH, ADAL_VER_LOW)

#define ADAL_VERSION_STRING     STR(ADAL_VER_HIGH) "." STR(ADAL_VER_LOW) "." STR(ADAL_VER_PATCH)
#define ADAL_VERSION_NSSTRING   @"" STR(ADAL_VER_HIGH) "." STR(ADAL_VER_LOW) "." STR(ADAL_VER_PATCH)

#define ADAL_VERSION_HELPER(high, low, patch) adalVersion_ ## high ## _ ## low ## _ ## patch
#define ADAL_VERSION_(high, low, patch) ADAL_VERSION_HELPER(high, low, patch)

// This is specially crafted so the name of the variable matches the full ADAL version
#define ADAL_VERSION_VAR ADAL_VERSION_(ADAL_VER_HIGH, ADAL_VER_LOW, ADAL_VER_PATCH)

#import "ADAuthenticationError+Internal.h"
#import "MSIDLogger+Internal.h"
#import "ADAuthenticationResult+Internal.h"

#import "NSString+MSIDExtensions.h"
#import "NSDictionary+MSIDExtensions.h"
#import "NSURL+MSIDExtensions.h"

#import "MSIDOAuth2Constants.h"
#import "ADALConstants.h"

@class ADAuthenticationResult;
@class MSIDTokenResponse;

/*! The completion block declaration. */
typedef void(^ADAuthenticationCallback)(ADAuthenticationResult* result);
typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);
typedef void(^MSIDTokenResponseCallback)(MSIDTokenResponse *response, ADAuthenticationError *error);

#if TARGET_OS_IPHONE
//iOS:
#   include <UIKit/UIKit.h>
typedef UIWebView WebViewType;
#else
//OS X:
#   include <WebKit/WebKit.h>
typedef WebView   WebViewType;
#endif


#import "ADAuthenticationRequest.h"

//Helper macro to initialize a variable named __where string with place in file details:
#define WHERE \
NSString* __where = [NSString stringWithFormat:@"In function: %s, file line #%u", __PRETTY_FUNCTION__, __LINE__]

//General macro for throwing exception named NSInvalidArgumentException
#define THROW_ON_CONDITION_ARGUMENT(CONDITION, ARG) \
{ \
    if (CONDITION) \
    { \
        WHERE; \
        MSID_LOG_ERROR(nil, @"InvalidArgumentException: %s %@", #ARG, __where); \
        @throw [NSException exceptionWithName: NSInvalidArgumentException \
                                       reason:@"Please provide a valid '" #ARG "' parameter." \
                                     userInfo:nil];  \
    } \
}

// Checks a selector NSString argument to a method for being null or empty. Throws NSException with name
// NSInvalidArgumentException if the argument is invalid:
#define THROW_ON_NIL_EMPTY_ARGUMENT(ARG) THROW_ON_CONDITION_ARGUMENT([NSString msidIsStringNilOrBlank:ARG], ARG);

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
argumentName:@#ARG correlationId:nil]; \
}

#define STRING_NIL_OR_EMPTY_CONDITION(ARG) [NSString msidIsStringNilOrBlank:ARG]
#define NIL_CONDITION(ARG) (!ARG)

#define RETURN_ON_INVALID_ARGUMENT(CONDITION, ARG, RET) \
{ \
    if (CONDITION) \
    { \
        WHERE; \
        MSID_LOG_ERROR(nil, @"InvalidArgumentError: %s %@", #ARG, __where); \
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
MSID_LOG_VERBOSE(nil, @"ADAL API call [Version - " ADAL_VERSION_STRING "] - %@", __where); \
}


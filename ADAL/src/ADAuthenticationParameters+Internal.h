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

//Protocol constants:
extern NSString* const OAuth2_Bearer;
extern NSString* const OAuth2_Authenticate_Header;
extern NSString* const OAuth2_Authorization;
extern NSString* const OAuth2_Authorization_Uri;
extern NSString* const OAuth2_Resource_Id;

//Error messages:
extern NSString* const InvalidHeader_NoBearer;
extern NSString* const MissingHeader;
extern NSString* const MissingAuthority;
extern NSString* const ConnectionError;
extern NSString* const InvalidResponse;
extern NSString* const UnauthorizedHTTStatusExpected;

/*! Contains non-public declarations of the ADAuthenticationParameters class.
 Exposed in a separate header for easier testing */
@interface ADAuthenticationParameters (Internal)

/*! Internal initializer, should be called only from within the class definitions
 or derived classes. */
-(id) initInternalWithParameters: (NSDictionary*) extractedParameters
                           error: (ADAuthenticationError* __autoreleasing*) error;

/*! Internal method. Extracts the challenge parameters from the Bearer contents in the authorize header. 
 Returns nil in case of error and if "error" parameter is not nil, adds the error details to this parameter. */
+ (NSDictionary*) extractChallengeParameters: (NSString*) headerContents
                                       error: (ADAuthenticationError* __autoreleasing*) error;

@end

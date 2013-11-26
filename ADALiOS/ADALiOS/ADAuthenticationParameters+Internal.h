// Created by Boris Vidolov on 10/10/13.
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


#import <ADALiOS/ADAuthenticationParameters.h>

//Protocol constants:
extern NSString* const OAuth2_Bearer;
extern NSString* const OAuth2_Authenticate_Header;
extern NSString* const OAuth2_Authorization;
extern NSString* const OAuth2_Authorization_Uri;

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
 or derived classes. 
 @param challengeHeaderContents: the contents of the authenticate challenge response header. 
 @param start: the starting point of the key-value pairs, containing the parameters of the challenge.*/
-(id) initInternalWithChallenge: (NSString*)challengeHeaderContents
                          start: (long) start;

/*! Finds the beginning of the  Bearer challenge in the "WWW-Authenticate" header contents. 
 Returns negative value (-1) and sets the error if Bearer challenge cannot be found. */
+ (long) extractChallenge: (NSString*) headerContents
                    error: (ADAuthenticationError* __autoreleasing*) error;

/*! Given a challenge, extracts the key-value pairs, containing the parameters and
puts them in the extractedParamters field. Additionally, sets the object properties,
if the header is in the correct format.
Returns false if it encounters incorrect format.
 @param: headerContents: the original header contents to be parsed.
 @param: start: The first character to start extracting the parameters from. Should be
 beyond the "Bearer " part*/
- (BOOL) extractChallengeItems: (NSString*) headerContents
                         start: (long) start;

@end

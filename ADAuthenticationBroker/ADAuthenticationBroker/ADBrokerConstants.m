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


#import "ADBrokerConstants.h"

NSString* const BROKER_ERROR_DOMAIN = @"ADBrokerErrorDomain";
NSString* const AUTHORITY = @"authority";
NSString* const REDIRECT_URI = @"redirect_uri";
NSString* const RESOURCE = @"resource";
NSString* const CLIENT_ID = @"client_id";
NSString* const BROKER_KEY = @"broker_key";
NSString* const USER_ID = @"user_id";
NSString* const EXTRA_QUERY_PARAMETERS = @"query_params";
NSString* const CORRELATION_ID = @"correlation_id";
NSString* const DEFAULT_GUID_FOR_NIL = @"CC3513A0-0E69-4B4D-97FC-DFB6C91EE132";

NSString* DEFAULT_AUTHORITY = @"https://login.windows.net/common/";
NSString* const BROKER_CLIENT_ID = @"29d9ed98-a469-4536-ade2-f981bc1d605e";
NSString* const BROKER_RESOURCE = @"https://graph.windows.net";
NSString* const BROKER_REDIRECT_URI = @"ms-appx-web://Microsoft.AAD.BrokerPlugin";
NSString* const DEFAULT_FIRST_PARTY_CLIENT_ID = @"";

NSString *const OAUTH2_ERROR_KEY = @"error";
NSString *const OAUTH2_GRANT_TYPE_KEY         = @"grant_type";
NSString *const OAUTH2_TOKEN_TYPE_KEY         = @"token_type";
NSString *const OAUTH2_PRIMARY_REFRESH_TOKEN_EXPIRES_KEY      = @"expires_in";
NSString *const OAUTH2_ID_TOKEN_KEY      = @"id_token";
NSString *const OAUTH2_REFRESH_TOKEN_KEY      = @"refresh_token";
NSString *const OAUTH2_SESSION_JWE_KEY      = @"session_key_jwe";
NSString *const CORRELATION_ID_RESPONSE  = @"correlation_id";
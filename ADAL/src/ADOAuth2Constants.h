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

#pragma once

extern NSString *const OAUTH2_ACCESS_TOKEN;
extern NSString *const OAUTH2_AUTHORIZATION;
extern NSString *const OAUTH2_AUTHORIZATION_CODE;
extern NSString *const OAUTH2_AUTHORIZATION_URI;
extern NSString *const OAUTH2_AUTHORITY;
extern NSString *const OAUTH2_AUTHORIZE_SUFFIX;
extern NSString *const OAUTH2_BEARER;
extern NSString *const OAUTH2_CLIENT_ID;
extern NSString *const OAUTH2_CLIENT_SECRET;
extern NSString *const OAUTH2_CODE;
extern NSString *const OAUTH2_ERROR;
extern NSString *const OAUTH2_ERROR_DESCRIPTION;
extern NSString *const OAUTH2_EXPIRES_IN;
extern NSString *const OAUTH2_GRANT_TYPE;
extern NSString *const OAUTH2_PLATFORM_ID;
extern NSString *const OAUTH2_REALM;
extern NSString *const OAUTH2_REDIRECT_URI;
extern NSString *const OAUTH2_REFRESH_TOKEN;
extern NSString *const OAUTH2_RESOURCE;
extern NSString *const OAUTH2_RESPONSE_TYPE;
extern NSString *const OAUTH2_SCOPE;
extern NSString *const OAUTH2_STATE;
extern NSString *const OAUTH2_TOKEN;
extern NSString *const OAUTH2_TOKEN_SUFFIX;
extern NSString *const OAUTH2_INSTANCE_DISCOVERY_SUFFIX;
extern NSString *const OAUTH2_TOKEN_TYPE;
extern NSString *const OAUTH2_LOGIN_HINT;
extern NSString *const OAUTH2_ID_TOKEN;
extern NSString *const OAUTH2_CORRELATION_ID_RESPONSE;
extern NSString *const OAUTH2_CORRELATION_ID_REQUEST;
extern NSString *const OAUTH2_CORRELATION_ID_REQUEST_VALUE;
extern NSString *const OAUTH2_SAML11_BEARER_VALUE;
extern NSString *const OAUTH2_SAML2_BEARER_VALUE;
extern NSString *const OAUTH2_SCOPE_OPENID_VALUE;
extern NSString *const OAUTH2_ASSERTION;

extern NSString *const ADAL_CLIENT_FAMILY_ID;

extern NSString *const BROKER_MAX_PROTOCOL_VERSION;
extern NSString *const BROKER_MESSAGE_VERSION;
extern NSString *const BROKER_APP_VERSION;
extern NSString *const BROKER_RESPONSE_KEY;
extern NSString *const BROKER_HASH_KEY;
extern NSString *const BROKER_INTUNE_RESPONSE_KEY;
extern NSString *const BROKER_INTUNE_HASH_KEY;

extern NSString *const ADAL_CLIENT_TELEMETRY;

//Diagnostic traces sent to the Azure Active Directory servers:
extern NSString *const ADAL_ID_PLATFORM;//The ADAL platform. iOS or OSX
extern NSString *const ADAL_ID_VERSION;
extern NSString *const ADAL_ID_CPU;//E.g. ARM64
extern NSString *const ADAL_ID_OS_VER;//iOS/OSX version
extern NSString *const ADAL_ID_DEVICE_MODEL;//E.g. iPhone 5S


extern NSString *const AUTH_FAILED; //Generic error.
extern NSString *const AUTH_FAILED_ERROR_CODE;
extern NSString *const AUTH_NON_PROTOCOL_ERROR; //A special error to denote that the error was not part of the protocol. E.g. a connection error.

extern NSString *const AUTH_FAILED_SERVER_ERROR;
extern NSString *const AUTH_FAILED_NO_STATE;
extern NSString *const AUTH_FAILED_BAD_STATE;
extern NSString *const AUTH_FAILED_NO_TOKEN;
extern NSString *const AUTH_FAILED_BAD_PARAMETERS;
extern NSString *const AUTH_FAILED_NO_CLIENTID;
extern NSString *const AUTH_FAILED_NO_REDIRECTURI;
extern NSString *const AUTH_FAILED_BUSY;

extern NSString *const AAD_SECURECONVERSATION_LABEL;

extern NSString *const AUTH_USERNAME_KEY;
extern NSString *const AUTH_CLOUD_INSTANCE_HOST_NAME;

extern NSString *const AUTH_PROTECTION_POLICY_REQUIRED;

extern NSString* const ADAL_BROKER_SCHEME;
extern NSString* const ADAL_BROKER_APP_REDIRECT_URI;
extern NSString* const ADAL_BROKER_APP_BUNDLE_ID;
extern NSString* const ADAL_BROKER_APP_BUNDLE_ID_DOGFOOD;

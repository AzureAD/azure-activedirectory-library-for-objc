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

NSString *const ADAL_CLIENT_FAMILY_ID = @"foci";

NSString *const ADAL_BROKER_MAX_PROTOCOL_VERSION              = @"max_protocol_ver";

NSString *const ADAL_BROKER_MESSAGE_VERSION          = @"msg_protocol_ver";
NSString *const ADAL_BROKER_APP_VERSION              = @"x-broker-app-ver";
NSString *const ADAL_BROKER_RESPONSE_KEY             = @"response";
NSString *const ADAL_BROKER_HASH_KEY                 = @"hash";
NSString *const ADAL_BROKER_INTUNE_RESPONSE_KEY      = @"intune_mam_token";
NSString *const ADAL_BROKER_INTUNE_HASH_KEY          = @"intune_mam_token_hash";
NSString *const ADAL_BROKER_NONCE_KEY                = @"broker_nonce";
NSString *const ADAL_MS_ENROLLMENT_ID                = @"microsoft_enrollment_id";

NSString *const ADAL_CLIENT_TELEMETRY           = @"x-ms-clitelem";

//Diagnostic traces sent to the Azure Active Directory servers:
NSString *const ADAL_ID_VERSION           = @"x-client-Ver";

NSString *const ADAL_AAD_SECURECONVERSATION_LABEL = @"AzureAD-SecureConversation";

NSString *const ADAL_AUTH_USERNAME_KEY                = @"username";
NSString *const ADAL_AUTH_CLOUD_INSTANCE_HOST_NAME    = @"cloud_instance_host_name";
NSString *const ADAL_AUTH_SUBERROR                    = @"suberror";
NSString *const ADAL_AUTH_PROTECTION_POLICY_REQUIRED  = @"protection_policy_required";
NSString *const ADAL_AUTH_ADDITIONAL_USER_IDENTIFIER  = @"adi";

//application constants
NSString* const ADAL_BROKER_SCHEME = @"msauth";
NSString* const ADAL_BROKER_NONCE_SCHEME = @"msauthv3";
NSString* const ADAL_BROKER_APP_REDIRECT_URI = @"urn:ietf:wg:oauth:2.0:oob";
NSString* const ADAL_BROKER_APP_BUNDLE_ID = @"com.microsoft.azureauthenticator";
NSString* const ADAL_BROKER_APP_BUNDLE_ID_DOGFOOD = @"com.microsoft.azureauthenticator-df";


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

#import <ADAL/ADAL.h>

#if MS_REMOTE_PKEYAUTH_CALLBACK && TARGET_OS_SIMULATOR

/// This block for the ADAL gets device identity (device has to be enrolled and compliant)
/// @param challengeUrl device CA challenge recieved from AAD
typedef NSString * _Nullable (^ADALRemotePkeyAuthResponseCallback)(NSString * _Nonnull challengeUrl);

@interface ADALAuthenticationContext (RemoteDeviceIdentity)
/// Enables In memory token cache
@property (class, nonatomic) BOOL isInMemoryTokenCacheEnabled;

/// Sets a block for the ADAL, which will be called once device CA request from AAD recieved to get device identity (device has to be enrolled and compliant)
/// @param callback The block autjentication challenge is sent.
+(void)setRemotePkeyAuthCallback:(nullable ADALRemotePkeyAuthResponseCallback)callback;

@end
#endif

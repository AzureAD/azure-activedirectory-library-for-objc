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

#import <Foundation/Foundation.h>

@protocol ADTokenCacheDelegate;

/*! The class stores global settings for the ADAL library. It is a singleton class
 and the alloc, init and new should not be called directly. The "sharedInstance" selector
 should be used instead to provide the settings instance. The class is not thread-safe.
 */
@interface ADAuthenticationSettings : NSObject
{
    int _requestTimeOut;
    uint _expirationBuffer;
#if !TARGET_OS_IPHONE
    id<ADTokenCacheDelegate> _defaultStorageDelegate;
#endif
}

/*! The static instance of the singleton settings class*/
+(nonnull ADAuthenticationSettings*) sharedInstance;

/*! The timeout used for any of the web requests. Specified in seconds. */
@property int requestTimeOut;

/*! When checking an access token for expiration we check if time to expiration
 is less than this value (in seconds) before making the request. The goal is to
 refresh the token ahead of its expiration and also not to return a token that is
 about to expire. */
@property uint expirationBuffer;

#if TARGET_OS_IPHONE
/*! Used for the webView. Default is YES.*/
@property BOOL enableFullScreen;
#endif //TARGET_OS_IPHONE

#if !TARGET_OS_IPHONE
@property (copy, nullable) id<ADTokenCacheDelegate> defaultStorageDelegate;
#endif

#if TARGET_OS_IPHONE
/*! The name of the keychain group to be used if sharing of cache between applications
 is desired. Can be nil. The property sets the appropriate value of defaultTokenCacheStore
 object. See apple's documentation for keychain groups: such groups require certain
 entitlements to be set by the applications. Additionally, access to the items in this group
 is only given to the applications from the same vendor. If this property is not set, the behavior
 will depend on the values in the entitlements file (if such exists) and may not result in token
 sharing. The property has no effect if other cache mechanisms are used (non-keychain).
 
 NOTE: Once an authentication context has been created with the default keychain
 group, or +[ADKeychainTokenCache defaultKeychainCache] has been called then
 this value cannot be changed. Doing so will throw an exception.
 */
- (nonnull NSString*)defaultKeychainGroup;
- (void)setDefaultKeychainGroup:(nullable NSString*)keychainGroup;
#endif // TARGET_OS_IPHONE

@end

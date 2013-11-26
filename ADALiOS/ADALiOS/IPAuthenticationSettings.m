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

#import "IPAuthorizationCache.h"
#import "IPAuthenticationSettings.h"

#import "WebAuthenticationBroker.h"

@implementation IPAuthenticationSettings
{
}

// The singleton instance of IPAuthenticationSettings
+ (IPAuthenticationSettings *)sharedInstance
{
    static IPAuthenticationSettings *settings = nil;
    static dispatch_once_t           predicate;
    
    dispatch_once( &predicate,
                  ^{
                      settings = [[[self class] allocPrivate] init];
                  });
    
    return settings;
}

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)init
{
    if ( ( self = [super init] ) != nil )
    {
        _enableTokenCaching = YES; // Default = YES
        _enableFullscreen   = NO;  // Default = NO, use form sheet
        _enableSSO          = NO;  // Default = NO, Assume server has wfresh=0
        
        NSString *bundleId  = [[NSBundle mainBundle] bundleIdentifier];
        
        if ( nil != bundleId )
        {
            // We cannot initialize these values unless we have a bundle identifier
            _clientId    = [[NSBundle mainBundle] bundleIdentifier];
            _redirectUri = [NSString stringWithFormat:@"%@://authorize", _clientId];
        }
        else
        {
            _clientId    = nil;
            _redirectUri = nil;
        }
        
        _platformId         = nil;
        
        _authorizationCache = IPAuthorizationMemoryCache.sharedInstance;
    }
    
    return self;
}

#pragma mark - Properties

@synthesize enableSSO          = _enableSSO;
@synthesize enableTokenCaching = _enableTokenCaching;

@synthesize clientId    = _clientId;
@synthesize redirectUri = _redirectUri;

#if TARGET_OS_IPHONE
// Resource Path is only use on iPhone/iPad
- (NSString *)resourcePath
{
    return [WebAuthenticationBroker resourcePath];
}

- (void)setResourcePath:(NSString *)resourcePath
{
    [WebAuthenticationBroker setResourcePath:resourcePath];
}
#endif

@end

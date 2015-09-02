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

#import <XCTest/XCTest.h>
#import "ADTokenCacheStoreKey.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADUserIdentifier.h"

@interface ADTokenCacheStoreKeyTests : XCTestCase
{
    NSString* mAuthority;
    //NSString* mResource;
    NSString* mClientId;
    NSString* mUserId;
    NSString* mUniqueId;
    NSString* _policy;
    ADUserIdentifierType mIdType;
    NSSet* mScopes;
}

@end

@implementation ADTokenCacheStoreKeyTests

- (void)reset
{
    mAuthority = @"https://login.windows.net/common";;
    //mResource = @"http://mywebApi.com";
    mClientId = @"myclientid";
    mUserId = @"myuser@contoso.com";
    mUniqueId = nil;
    mIdType = RequiredDisplayableId;
    mScopes = [NSSet setWithObjects:@"planetarydefense.fire", nil];
}

- (void)setUp
{
    [super setUp];
    [self reset];
}

- (void)tearDown
{
    [super tearDown];
}

- (ADTokenCacheStoreKey*)createKey:(ADAuthenticationError* __autoreleasing *)error
{
    return [ADTokenCacheStoreKey keyWithAuthority:mAuthority
                                         clientId:mClientId
                                           userId:mUserId
                                         uniqueId:mUniqueId
                                           idType:mIdType
                                           policy:_policy
                                           scopes:mScopes
                                            error:error];
}

- (void)testCreate
{
    ADAuthenticationError* error = nil;
    ADTokenCacheStoreKey* key = [self createKey:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    
    //Bad authority:
    error = nil;
    ADTokenCacheStoreKey* badKey = [ADTokenCacheStoreKey keyWithAuthority:nil
                                                                 clientId:mClientId
                                                                   userId:nil
                                                                 uniqueId:nil
                                                                   idType:RequiredDisplayableId
                                                                   policy:nil
                                                                   scopes:nil
                                                                    error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority"
                             returnedObject:badKey
                                      error:error];
    error = nil;
    badKey = [ADTokenCacheStoreKey keyWithAuthority:@"   "
                                           clientId:mClientId
                                             userId:nil
                                           uniqueId:nil
                                             idType:RequiredDisplayableId
                                             policy:nil
                                             scopes:nil
                                              error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority"
                             returnedObject:badKey
                                      error:error];

    //Bad clientId
    error = nil;
    badKey = [ADTokenCacheStoreKey keyWithAuthority:mAuthority
                                           clientId:nil
                                             userId:nil
                                           uniqueId:nil
                                             idType:RequiredDisplayableId
                                             policy:nil
                                             scopes:nil
                                              error:&error];
    [self adValidateFactoryForInvalidArgument:@"clientId"
                             returnedObject:badKey
                                      error:error];
    error = nil;
    badKey = [ADTokenCacheStoreKey keyWithAuthority:mAuthority
                                           clientId:@"    "
                                             userId:nil
                                           uniqueId:nil
                                             idType:RequiredDisplayableId
                                             policy:nil
                                             scopes:nil
                                              error:&error];
    [self adValidateFactoryForInvalidArgument:@"clientId"
                             returnedObject:badKey
                                      error:error];
    
    error = nil;
    ADTokenCacheStoreKey* normal = [ADTokenCacheStoreKey keyWithAuthority:mAuthority
                                                                 clientId:mClientId
                                                                   userId:nil
                                                                 uniqueId:nil
                                                                   idType:RequiredDisplayableId
                                                                   policy:nil
                                                                   scopes:nil
                                                                    error:&error];
    ADAssertNoError;
    XCTAssertNotNil(normal);
}

-(void) assertKey: (ADTokenCacheStoreKey*) key1
         equalsTo: (ADTokenCacheStoreKey*) key2
{
    XCTAssertTrue([key1 isEqual:key2]);
    XCTAssertTrue([key2 isEqual:key1]);
    XCTAssertEqual(key1.hash, key2.hash);
}

-(void) assertKey: (ADTokenCacheStoreKey*) key1
      notEqualsTo: (ADTokenCacheStoreKey*) key2
{
    XCTAssertFalse([key1 isEqual:key2]);
    XCTAssertFalse([key2 isEqual:key1]);
    XCTAssertNotEqual(key1.hash, key2.hash);
}

- (void)testCompare
{
    ADAuthenticationError* error = nil;
    ADTokenCacheStoreKey* normal = [self createKey:&error];
    ADAssertNoError;
    XCTAssertNotNil(normal);
    [self assertKey:normal equalsTo:normal];//Self
    [self assertKey:normal notEqualsTo:nil];
    
    {
        error = nil;
        ADTokenCacheStoreKey* same = [self createKey:&error];
        ADAssertNoError;
        XCTAssertNotNil(same);
        [self assertKey:normal equalsTo:normal];
    }
    
    {
        error = nil;
        mAuthority = @"https://login.windows.com/common";
        ADTokenCacheStoreKey* differentAuth = [self createKey:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentAuth);
        [self assertKey:normal notEqualsTo:differentAuth];
    }
    
    {
        error = nil;
        mClientId = @"another clientid";
        ADTokenCacheStoreKey* differentClient = [self createKey:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentClient);
        [self assertKey:normal notEqualsTo:differentClient];
    }
}


@end

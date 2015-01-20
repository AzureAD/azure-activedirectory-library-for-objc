#import <XCTest/XCTest.h>
#import <libkern/OSAtomic.h>
#import "ADBrokerKeychainTokenCacheStore.h"
#import <ADALiOS/ADTokenCacheStoring.h>
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALiOS/ADUserInformation.h>
#import <ADALiOS/ADTokenCacheStoreKey.h>
#import "NSString+ADBrokerHelperMethods.h"

const int sMaxLoggerThreadsDuration = 5;//In seconds
const int sMaxLoggerTestThreads = 100;
volatile int32_t sLoggerTestThreadsCompleted = 0;
dispatch_semaphore_t sLoggerTestCompletedSignal;
NSString* const sIdTokenClaims = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224170,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"someone@example.com\",\"unique_name\":\"someone@example.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"One\",\"given_name\":\"Some\",\"altsecid\":\"Some Guest id\",\"idp\":\"Fake IDP\",\"email\":\"fake e-mail\"}";
NSString* const sIDTokenHeader = @"{\"typ\":\"JWT\",\"alg\":\"none\"}";

@interface ADBrokerKeychainStoreTests : XCTestCase
@end

@implementation ADBrokerKeychainStoreTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testDifferentHashKey
{
    ADAuthenticationError* error;
    ADBrokerKeychainTokenCacheStore *store = [[ADBrokerKeychainTokenCacheStore  alloc] initWithAppKey:@"key1"];
    [store removeAllWithError:&error];
    XCTAssertTrue([self cacheSize:store] == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    [store addOrUpdateItem:item error:&error];
    XCTAssertNil(error);
    
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADTokenCacheStoreItem* outItem = [store getItemWithKey:key userId:nil error:&error];
    XCTAssertNotNil(outItem);
    XCTAssertNil(error);
    outItem = nil;
    
    store = [[ADBrokerKeychainTokenCacheStore  alloc] initWithAppKey:@"key2"];
    key = [item extractKeyWithError:&error];
    outItem = [store getItemWithKey:key userId:nil error:&error];
    XCTAssertNil(outItem);
    XCTAssertNil(error);
}


-(long) cacheSize:(ADBrokerKeychainTokenCacheStore*) store
{
    ADAuthenticationError* error = nil;
    NSArray* all = [store allItemsWithError:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(all);
    return all.count;
}

//Creates an new item with all of the properties having correct
//values

-(ADTokenCacheStoreItem*) adCreateCacheItem{
    return [self adCreateCacheItem:@"resource"];
}

-(ADTokenCacheStoreItem*) adCreateCacheItem:(NSString*) resource
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = resource;
    item.authority = @"https://login.windows.net/sometenant.com";
    item.clientId = @"client id";
    item.accessToken = @"access token";
    item.refreshToken = @"refresh token";
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    item.userInformation = [self adCreateUserInformation];
    item.accessTokenType = @"access token type";
    
    return item;
}

-(ADUserInformation*) adCreateUserInformation
{
    ADAuthenticationError* error = nil;
    //This one sets the "userId" property:
    NSString* id_token = [NSString stringWithFormat:@"%@.%@.",
                          [sIDTokenHeader adBase64UrlEncode],
                          [sIdTokenClaims adBase64UrlEncode]];
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:id_token error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(userInfo, "Nil user info returned.");
    return userInfo;
}

@end
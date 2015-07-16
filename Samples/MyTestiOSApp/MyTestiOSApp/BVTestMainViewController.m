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


#import "BVTestMainViewController.h"
#import <ADALiOS/ADAL.h>
#import "BVSettings.h"
#import "BVTestInstance.h"
#import "BVApplicationData.h"


ADAuthenticationContext* context = nil;

@interface BVTestMainViewController ()
- (IBAction)pressMeAction:(id)sender;
- (IBAction)clearCachePressed:(id)sender;
- (IBAction)getUsersPressed:(id)sender;
- (IBAction)expireAllPressed:(id)sender;
- (IBAction)promptAlways:(id)sender;
- (IBAction)acquireTokenSilentAction:(id)sender;
@end

static NSString* _StringForLevel(ADAL_LOG_LEVEL level)
{
    switch (level)
    {
        case ADAL_LOG_LEVEL_ERROR : return @"ERR";
        case ADAL_LOG_LEVEL_INFO : return @"INF";
        case ADAL_LOG_LEVEL_VERBOSE : return @"VER";
        case ADAL_LOG_LEVEL_WARN : return @"WAR";
        default:
            return @"???";
    }
}

@implementation BVTestMainViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    //settings.credentialsType = AD_CREDENTIALS_EMBEDDED;
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(consumeToken)
     name:UIApplicationWillEnterForegroundNotification object:nil];
    
    // Do any additional setup after loading the view, typically from a nib.
    [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];//Log everything
    
    mTestData = [BVSettings new];
    mAADInstance = mTestData.testAuthorities[sAADTestInstance];
    
    [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode)
    {
        NSString* logLine = nil;
        if (errorCode == AD_ERROR_SUCCEEDED)
        {
            logLine = [NSString stringWithFormat:@"%@ %@ - %@", _StringForLevel(logLevel), message, additionalInformation];
        }
        else
        {
            logLine = [NSString stringWithFormat:@"%@ (error: %d) %@ - %@", _StringForLevel(logLevel), errorCode, message, additionalInformation];
        }
        NSLog(@"%@", logLine);
        [self appendToResults:logLine];
    }];
    //[ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
}
- (void)clearResults
{
    dispatch_async(dispatch_get_main_queue(), ^{
       _resultView.text = @"";
    });
}

- (void)appendToResults:(NSString*)message
{
    dispatch_async(dispatch_get_main_queue(), ^
    {
        NSTextStorage* storage = _resultView.textStorage;
        [storage appendAttributedString:[[NSAttributedString alloc] initWithString:[message stringByAppendingString:@"\n"]]];
    });
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [ADLogger setLogCallBack:nil];
}

-(void) consumeToken
{
    BVApplicationData* data = [BVApplicationData getInstance];
    if(!data.result)
    {
        return;
    }
    
    NSString* resultString = nil;
    if(data.result.status == AD_SUCCEEDED)
    {
        resultString = [NSString stringWithFormat:@"-- TOKEN FROM BROKER --\n%@", data.result.accessToken];
    }
    else
    {
        resultString = [NSString stringWithFormat:@"-- ERROR FROM BROKER --\n%@", data.result.error.errorDetails];
    }
    
    [self appendToResults:resultString];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - Flipside View Controller

- (void)flipsideViewControllerDidFinish:(BVTestFlipsideViewController *)controller
{
    [self dismissViewControllerAnimated:YES completion:nil];
    
    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
    settings.enableFullScreen = [mAADInstance enableFullScreen];
    settings.requestTimeOut = [mAADInstance requestTimeout];
}

- (void)popoverControllerDidDismissPopover:(UIPopoverController *)popoverController
{
    self.flipsidePopoverController = nil;
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
    if ([[segue identifier] isEqualToString:@"showAlternate"]) {
        [[segue destinationViewController] setDelegate:self];
    }
}

- (IBAction)togglePopover:(id)sender
{
    if (self.flipsidePopoverController) {
        [self.flipsidePopoverController dismissPopoverAnimated:YES];
        self.flipsidePopoverController = nil;
    } else {
        [self performSegueWithIdentifier:@"showAlternate" sender:sender];
    }
}

- (IBAction)pressMeAction:(id)sender
{
    NSString* authority = mAADInstance.authority;//params.authority;
    NSString* clientId = mAADInstance.clientId;
    NSString* resourceString = mAADInstance.resource;
    NSString* redirectUri = mAADInstance.redirectUri;
    NSString* userId = [_tfUserId text];
    ADAuthenticationError* error = nil;
    //[weakSelf setStatus:[NSString stringWithFormat:@"Authority: %@", params.authority]];
    context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                        validateAuthority:mAADInstance.validateAuthority
                                                                    error:&error];
    if (!context)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    context.parentController = self;
    
    ADUserIdentifier* adUserId = [ADUserIdentifier identifierWithId:userId type:(ADUserIdentifierType)[_scUserType selectedSegmentIndex]];
    [context acquireTokenWithResource:resourceString
                             clientId:clientId
                          redirectUri:[NSURL URLWithString:redirectUri]
                       promptBehavior:[_scPromptBehavior selectedSegmentIndex]
                       userIdentifier:adUserId
                 extraQueryParameters:nil
                      completionBlock:^(ADAuthenticationResult *result)
    {
        if (result.status != AD_SUCCEEDED)
        {
            [self appendToResults:result.error.errorDetails];
            return;
        }
        
        ADUserInformation* userInfo = result.tokenCacheStoreItem.userInformation;
        if (!userInfo)
        {
            [self appendToResults:@"Succesfully signed in but no user info?"];
            return;
        }
        
        [self appendToResults:[NSString stringWithFormat:@"Successfully logged in as %@", userInfo.userId]];
        [self appendToResults:[NSString stringWithFormat:@"allclaims=%@", userInfo.allClaims]];
    }];
}


- (IBAction)acquireTokenSilentAction:(id)sender
{
    [self clearResults];
    [self appendToResults:@"Starting Acquire Token Silent."];
    
    //TODO: implement the 401 challenge response in the test Azure app. Temporarily using another one:
    NSString* __block resourceString = @"http://testapi007.azurewebsites.net/api/WorkItem";
    //    NSURL* resource = [NSURL URLWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    ADAuthenticationError * error;
    
    //401 worked, now try to acquire the token:
    //TODO: replace the authority here with the one that comes back from 'params'
    NSString* authority = mAADInstance.authority;//params.authority;
    NSString* clientId = mAADInstance.clientId;
    NSString* userId = mAADInstance.userId;
    //NSString* __block resourceString = mAADInstance.resource;
    NSString* redirectUri = mAADInstance.redirectUri;
    [self appendToResults:[NSString stringWithFormat:@"Authority: %@", authority]];
    context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                                    error:&error];
    if (!context)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    context.parentController = self;
    
    [context acquireTokenSilentWithResource:resourceString
                                   clientId:clientId
                                redirectUri:[NSURL URLWithString:redirectUri]
                                     userId:userId
                            completionBlock:^(ADAuthenticationResult *result) {
        if (result.status != AD_SUCCEEDED)
        {
            [self appendToResults:result.error.errorDetails];
            return;
        }
        
        [self appendToResults:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
    }];
}

- (IBAction)clearCachePressed:(id)sender
{
    [self clearResults];
    ADAuthenticationError* error;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* allItems = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    NSString* status = nil;
    if (allItems.count > 0)
    {
        [cache removeAll:&error];
        if (error)
        {
            status = error.errorDetails;
        }
        else
        {
            status = @"Items removed.";
        }
    }
    else
    {
        status = @"Nothing in the cache.";
    }
    NSHTTPCookieStorage* cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = cookieStorage.cookies;
    if (cookies.count)
    {
        for(NSHTTPCookie* cookie in cookies)
        {
            [cookieStorage deleteCookie:cookie];
        }
        status = [status stringByAppendingString:@" Cookies cleared."];
    }
    [self appendToResults:status];
}

- (IBAction)getUsersPressed:(id)sender
{
    [self clearResults];
    ADAuthenticationError* error;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    NSMutableSet* users = [NSMutableSet new];
    NSMutableString* usersStr = [NSMutableString new];
    for(ADTokenCacheStoreItem* item in array)
    {
        ADUserInformation *user = item.userInformation;
        if (!item.userInformation)
        {
            user = [ADUserInformation userInformationWithUserId:@"Unknown user" error:nil];
        }
        if (![users containsObject:user.userId])
        {
            //New user, add and print:
            [users addObject:user.userId];
            [usersStr appendFormat:@"%@: %@ %@", user.userId, user.givenName, user.familyName];
        }
    }
    [self appendToResults:usersStr];
}

-(NSString*) processAccessToken: (NSString*) accessToken
{
    //Add any future processing of the token here (e.g. opening to see what is inside):
    return accessToken;
}

- (IBAction)expireAllPressed:(id)sender
{
    ADAuthenticationError* error;
    [self clearResults];
    [self appendToResults:@"Attempt to expire..."];
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    for(ADTokenCacheStoreItem* item in array)
    {
        item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
        [cache addOrUpdateItem:item error:&error];
    }
    if (error)
    {
        [self appendToResults:error.errorDetails];
    }
    else
    {
        [self appendToResults:@"Done."];
    }
}

- (IBAction)promptAlways:(id)sender
{
    [self clearResults];
    [self appendToResults:@"Setting prompt always..."];
    ADAuthenticationError* error;
    context = [ADAuthenticationContext authenticationContextWithAuthority:mAADInstance.authority
                                                        validateAuthority:mAADInstance.validateAuthority
                                                                    error:&error];
    if (!context)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    
    [context acquireTokenWithResource:mAADInstance.resource
                             clientId:mAADInstance.clientId
                          redirectUri:[NSURL URLWithString:mAADInstance.redirectUri]
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:mAADInstance.userId
                 extraQueryParameters:mAADInstance.extraQueryParameters
                      completionBlock:^(ADAuthenticationResult *result)
     {
         if (result.status != AD_SUCCEEDED)
         {
             [self appendToResults:result.error.errorDetails];
             return;
         }
         
         [self appendToResults:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
         NSLog(@"Access token: %@", result.accessToken);
     }];
    
    
}


@end

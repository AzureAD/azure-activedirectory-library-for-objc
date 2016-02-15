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


#import "ADTestMainViewController.h"
#import <ADAL/ADAL.h>
#import "ADTestAppSettings.h"
#import "ADTestInstance.h"
#import "ADTestApplicationData.h"


ADAuthenticationContext* context = nil;

@interface ADTestMainViewController ()
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

@implementation ADTestMainViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    //settings.credentialsType = AD_CREDENTIALS_EMBEDDED;
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(consumeToken)
     name:UIApplicationWillEnterForegroundNotification object:nil];
    
    // Do any additional setup after loading the view, typically from a nib.
    [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];//Log everything
    
    mTestData = [ADTestAppSettings new];
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
    ADTestApplicationData* data = [ADTestApplicationData getInstance];
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

- (void)flipsideViewControllerDidFinish:(ADTestFlipsideViewController *)controller
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
    if (!userId || userId.length == 0)
    {
        userId = mAADInstance.userId;
    }
    
    ADAuthenticationError* error = nil;
    //[weakSelf setStatus:[NSString stringWithFormat:@"Authority: %@", params.authority]];
    context = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                        validateAuthority:mAADInstance.validateAuthority
                                                                    error:&error];
    [context setCredentialsType:AD_CREDENTIALS_AUTO];
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
        
        ADUserInformation* userInfo = result.tokenCacheItem.userInformation;
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
    ADAuthenticationError * error = nil;
    
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
        
        [self appendToResults:[self processAccessToken:result.tokenCacheItem.accessToken]];
    }];
}

- (IBAction)clearCachePressed:(id)sender
{
    [self clearResults];
    ADAuthenticationError* error = nil;
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    NSArray* allItems = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    NSString* status = nil;
    
    if (allItems.count > 0)
    {
        for (ADTokenCacheItem* item in allItems)
        {
            [cache removeItem:item error:nil];
        }
        status = @"Items removed.";
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
    ADAuthenticationError* error = nil;
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    NSMutableSet* users = [NSMutableSet new];
    NSMutableString* usersStr = [NSMutableString new];
    for(ADTokenCacheItem* item in array)
    {
        ADUserInformation *user = item.userInformation;
        if (!item.userInformation)
        {
            if (![users containsObject:@"<ADFS User>"])
            {
                [users addObject:@"<ADFS User>"];
                [usersStr appendString:@"<ADFS User>"];
            }
        }
        else if (![users containsObject:user.userId])
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
    // TODO: This requires using internal APIs. It's not an addOrUpdate is not something
    //       we have any desire to make public.
    /*
    ADAuthenticationError* error = nil;
    [self clearResults];
    [self appendToResults:@"Attempt to expire..."];
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [self appendToResults:error.errorDetails];
        return;
    }
    for(ADTokenCacheItem* item in array)
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
     */
    
}

- (IBAction)promptAlways:(id)sender
{
    [self clearResults];
    [self appendToResults:@"Setting prompt always..."];
    ADAuthenticationError* error = nil;
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
         
         [self appendToResults:[self processAccessToken:result.tokenCacheItem.accessToken]];
         NSLog(@"Access token: %@", result.accessToken);
     }];
    
    
}


@end

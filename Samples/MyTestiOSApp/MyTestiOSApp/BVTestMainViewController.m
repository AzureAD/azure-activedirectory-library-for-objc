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
#import <ADALiOS/ADAuthenticationContext.h>
#import <ADALiOS/ADAuthenticationParameters.h>
#import <ADALiOS/ADAuthenticationSettings.h>
#import <ADALiOS/ADLogger.h>
#import <ADALiOS/ADInstanceDiscovery.h>
#import "BVSettings.h"
#import "BVTestInstance.h"

@interface BVTestMainViewController ()
@property (weak, nonatomic) IBOutlet UILabel *resultLabel;
- (IBAction)pressMeAction:(id)sender;
- (IBAction)clearCachePressed:(id)sender;
- (IBAction)getUsersPressed:(id)sender;
- (IBAction)refreshTokenPressed:(id)sender;
- (IBAction)expireAllPressed:(id)sender;
- (IBAction)promptAlways:(id)sender;
- (IBAction)samlAssertionPressed:(id)sender;

@end

@implementation BVTestMainViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];//Log everything
    
    mTestData = [BVSettings new];
    mAADInstance = mTestData.testAuthorities[sAADTestInstance];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - Flipside View Controller

- (void)flipsideViewControllerDidFinish:(BVTestFlipsideViewController *)controller
{
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
        [self dismissViewControllerAnimated:YES completion:nil];
    } else {
        [self.flipsidePopoverController dismissPopoverAnimated:YES];
    }
}

- (void)popoverControllerDidDismissPopover:(UIPopoverController *)popoverController
{
    self.flipsidePopoverController = nil;
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
    if ([[segue identifier] isEqualToString:@"showAlternate"]) {
        [[segue destinationViewController] setDelegate:self];
        
        if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad) {
            UIPopoverController *popoverController = [(UIStoryboardPopoverSegue *)segue popoverController];
            self.flipsidePopoverController = popoverController;
            popoverController.delegate = self;
        }
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

-(void) setStatus: (NSString*) status
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.resultLabel setText:status];
    });
}

- (IBAction)samlAssertionPressed:(id)sender
{
    BVTestMainViewController* __weak weakSelf = self;
    NSString* authority = mAADInstance.authority;//params.authority;
    NSString* clientId = mAADInstance.clientId;
    NSString* resourceString = mAADInstance.resource;
    ADAuthenticationError * error;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:mAADInstance.validateAuthority error:&error];
    if (!context)
    {
        [weakSelf setStatus:error.errorDetails];
        return;
    }
    
    [context acquireTokenForAssertion:@"" assertionType:AD_SAML1_1 resource:resourceString clientId:clientId userId:@"kpanwar@microsoft.com" completionBlock:^(ADAuthenticationResult *result) {
        if (result.status != AD_SUCCEEDED)
        {
            [weakSelf setStatus:result.error.errorDetails];
            return;
        }
        
        [weakSelf setStatus:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
    }];
}


- (IBAction)pressMeAction:(id)sender
{
    BVTestMainViewController* __weak weakSelf = self;
    [self.resultLabel setText:@"Starting 401 challenge."];
    
    //TODO: implement the 401 challenge response in the test Azure app. Temporarily using another one:
    NSString* __block resourceString = @"http://testapi007.azurewebsites.net/api/WorkItem";
    NSURL* resource = [NSURL URLWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    [ADAuthenticationParameters parametersFromResourceUrl:resource completionBlock:^(ADAuthenticationParameters * params, ADAuthenticationError * error)
     {
         if (!params)
         {
             [weakSelf setStatus:error.errorDetails];
             return;
         }
         
         //401 worked, now try to acquire the token:
         //TODO: replace the authority here with the one that comes back from 'params'
         NSString* authority = mAADInstance.authority;//params.authority;
         NSString* clientId = mAADInstance.clientId;
         resourceString = mAADInstance.resource;
         NSString* redirectUri = mAADInstance.redirectUri;
         NSString* userId = mAADInstance.userId;
         [weakSelf setStatus:[NSString stringWithFormat:@"Authority: %@", params.authority]];
         ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:mAADInstance.validateAuthority error:&error];
         if (!context)
         {
             [weakSelf setStatus:error.errorDetails];
             return;
         }
         context.parentController = self;
         
         [context acquireTokenWithResource:resourceString
                                  clientId:clientId
                               redirectUri:[NSURL URLWithString:redirectUri]
                                    userId:userId
                      extraQueryParameters:mAADInstance.extraQueryParameters
                           completionBlock:^(ADAuthenticationResult *result) {
                               if (result.status != AD_SUCCEEDED)
                               {
                                   [weakSelf setStatus:result.error.errorDetails];
                                   return;
                               }
                               
                               [weakSelf setStatus:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
                           }];
     }];
}

- (IBAction)clearCachePressed:(id)sender
{
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* allItems = [cache allItemsWithError:&error];
    if (error)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    NSString* status = nil;
    if (allItems.count > 0)
    {
        [cache removeAllWithError:&error];
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
    [self setStatus:status];
}

- (IBAction)getUsersPressed:(id)sender
{
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItemsWithError:&error];
    if (error)
    {
        [self setStatus:error.errorDetails];
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
    [self setStatus:usersStr];
}

-(NSString*) processAccessToken: (NSString*) accessToken
{
    //Add any future processing of the token here (e.g. opening to see what is inside):
    return accessToken;
}

- (IBAction)refreshTokenPressed:(id)sender
{
    NSString* authority = mAADInstance.authority;
    NSString* clientId = mAADInstance.clientId;
    NSString* resourceString =mAADInstance.resource;
    [self setStatus:@"Attemp to refresh..."];
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO error:&error];
    if (!context)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    //We will leverage a multi-resource refresh token:
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:authority resource:resourceString clientId:clientId error:&error];
    if (!key)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    id<ADTokenCacheStoring> cache = context.tokenCacheStore;
    ADTokenCacheStoreItem* item = [cache getItemWithKey:key userId:mAADInstance.userId error:nil];
    if (!item)
    {
        [self setStatus:@"Missing cache item."];
        return;
    }
    BVTestMainViewController* __weak weakSelf = self;
    [context acquireTokenByRefreshToken:item.refreshToken
                               clientId:clientId
                               resource:resourceString
                        completionBlock:^(ADAuthenticationResult *result)
     {
         if (result.error)
         {
             [weakSelf setStatus:result.error.errorDetails];
         }
         else
         {
             [weakSelf setStatus:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
         }
     }];
}

- (IBAction)expireAllPressed:(id)sender
{
    ADAuthenticationError* error = nil;
    [self setStatus:@"Attempt to expire..."];
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItemsWithError:&error];
    if (error)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    for(ADTokenCacheStoreItem* item in array)
    {
        item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
        [cache addOrUpdateItem:item error:&error];
    }
    if (error)
    {
        [self setStatus:error.errorDetails];
    }
    else
    {
        [self setStatus:@"Done."];
    }
}

- (IBAction)promptAlways:(id)sender
{
    [self setStatus:@"Setting prompt always..."];
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:mAADInstance.authority error:&error];
    if (!context)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    
    BVTestMainViewController* __weak weakSelf = self;
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
             [weakSelf setStatus:result.error.errorDetails];
             return;
         }
         
         [weakSelf setStatus:[self processAccessToken:result.tokenCacheStoreItem.accessToken]];
         NSLog(@"Access token: %@", result.accessToken);
     }];
    
    
}


@end

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

#import "ViewController.h"
#import "AppDelegate.h"
#import "AccountDetailsViewController.h"
#import <ADAuthenticationBroker/ADBrokerKeychainTokenCacheStore.h>
#import <ADAuthenticationBroker/ADBrokerConstants.h>
#import <ADAuthenticationBroker/ADBrokerContext.h>
#import <ADALiOS/ADAuthenticationError.h>
#import <ADALiOS/ADUserInformation.h>
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALiOS/ADAuthenticationSettings.h>
#import <ADALiOS/ADTokenCacheStoring.h>
#import <ADAuthenticationBroker/ADBrokerUserAccount.h>

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITableView* tableView;
- (IBAction)addUserPressed:(id)sender;
- (IBAction)clearKeychainPressed:(id)sender;
//- (IBAction)getUsersPressed:(id)sender;

@end

@implementation ViewController

NSMutableArray* users;

-(void) loadView
{
    [super loadView];
}

-(void) viewWillAppear:(BOOL)animated
{
    [self getAllAccounts:YES];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    AppDelegate *appDelegate = (AppDelegate*)[[UIApplication sharedApplication] delegate];
    NSString* upnInRequest = nil;
    BOOL isBrokerRequest = [ADBrokerContext isBrokerRequest:appDelegate._url
                                                  returnUpn:&upnInRequest];
    if(isBrokerRequest)
    {
        [self getAllAccounts];
        if(upnInRequest || users.count == 0)
        {
            [ADBrokerContext invokeBrokerForSourceApplication:[appDelegate._url absoluteString]
                                            sourceApplication:appDelegate._sourceApplication
                                              completionBlock:^(ADAuthenticationResult *result) {
                                                  appDelegate._url = nil;
                                                  appDelegate._sourceApplication = nil;
                                              }];
        }
    }
    if(!users || users.count == 0)
    {
        users = [NSMutableArray new];
        [self getAllAccounts];
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)clearKeychainPressed:(id)sender
{
    
    ViewController* __weak weakSelf = self;
    id<ADTokenCacheStoring> cache = [ADBrokerKeychainTokenCacheStore new];
    ADAuthenticationError *error = nil;
    long count = (unsigned long)[[cache allItemsWithError:&error] count];
    if (error)
    {
        return;
    }
    
    [cache removeAllWithError:&error];
    if (error)
    {
        return;
    }
    [self getAllAccounts:YES];
}


- (IBAction)addUserPressed:(id)sender
{
    ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:DEFAULT_AUTHORITY];
    [ctx acquireAccount:nil
               clientId:BROKER_CLIENT_ID
               resource:BROKER_RESOURCE
            redirectUri:BROKER_REDIRECT_URI
        completionBlock:^(ADAuthenticationResult *result) {
        if(result.status != AD_SUCCEEDED)
        {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Error"
                                                            message:result.error.errorDetails
                                                           delegate:self
                                                  cancelButtonTitle:@"OK"
                                                  otherButtonTitles:nil];
            [alert show];
        }
        else{
            [self getAllAccounts:YES];
        }
    }];
}



- (void) getAllAccounts
{
    [self getAllAccounts:NO];
}

- (void) getAllAccounts:(BOOL) refreshList
{
    NSArray *accounts = [ADBrokerContext getAllAccounts:nil];
        [users removeAllObjects];
        [users addObjectsFromArray:accounts];
        if(refreshList)
        {
        dispatch_async(dispatch_get_main_queue(),^{
            [_tableView reloadData];
        });
        }
}

- (void) addUserToList:(ADBrokerUserAccount*) account
{
    [users addObject:account];
    NSIndexPath *indexPath = [NSIndexPath indexPathForRow:[users indexOfObject:account] inSection:0];
    [self.tableView beginUpdates];
    [self.tableView
     insertRowsAtIndexPaths:@[indexPath]withRowAnimation:UITableViewRowAnimationBottom];
    [self.tableView endUpdates];
}


// delegate methods
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return [users count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *simpleTableIdentifier = @"SimpleTableItem";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:simpleTableIdentifier];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:simpleTableIdentifier];
    }
    
    ADBrokerUserAccount* account = [users objectAtIndex:indexPath.row];
    ADUserInformation* info = account.userInformation;
    cell.textLabel.text = info.getUpn;
    if(account.isWorkplaceJoined)
    {
        cell.backgroundColor = [UIColor greenColor];
    }
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    ADBrokerUserAccount* account = [users objectAtIndex:indexPath.row];
    ADUserInformation* info = account.userInformation;
    AppDelegate *appDelegate = (AppDelegate*)[[UIApplication sharedApplication] delegate];
    NSString* upnInRequest = nil;
    BOOL isBrokerRequest = [ADBrokerContext isBrokerRequest:appDelegate._url
                                                  returnUpn:&upnInRequest];
    if(isBrokerRequest)
    {
        [self getAllAccounts];
        if(upnInRequest || users.count == 0)
        {
            [ADBrokerContext invokeBrokerForSourceApplication:[appDelegate._url absoluteString]
                                            sourceApplication:appDelegate._sourceApplication
                                                          upn:info.getUpn
                                              completionBlock:^(ADAuthenticationResult *result) {
                                                  appDelegate._url = nil;
                                                  appDelegate._sourceApplication = nil;
                                              }];
        }
    }
    else
    {
        AccountDetailsViewController *detailsController = [self.storyboard instantiateViewControllerWithIdentifier:@"AccountDetailsViewController"];
        [detailsController setModalPresentationStyle:UIModalPresentationFullScreen];
        detailsController.account = account;
        [self.navigationController pushViewController:detailsController
                                                animated:YES];
    }
}



@end

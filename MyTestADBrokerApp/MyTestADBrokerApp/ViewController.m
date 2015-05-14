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
#import <ADAuthenticationBroker/ADBrokerConstants.h>
#import <ADAuthenticationBroker/ADBrokerContext.h>
#import <ADALiOS/ADAuthenticationError.h>
#import <ADALiOS/ADUserInformation.h>
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALiOS/ADAuthenticationSettings.h>
#import <ADALiOS/ADTokenCacheStoring.h>
#import <ADAuthenticationBroker/ADBrokerUserAccount.h>
#import <ADAuthenticationBroker/ADBrokerSettings.h>


@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITableView* tableView;
- (IBAction)addUserPressed:(id)sender;
- (IBAction)clearKeychainPressed:(id)sender;
- (IBAction)clearLogPressed:(id)sender;
- (IBAction)emailLogPressed:(id)sender;
@end

@implementation ViewController

NSMutableArray* users;

-(void) loadView
{
    [super loadView];
    [self registerForNotifications];
}

- (void)registerForNotifications
{
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(yourCustomMethod:)
                                                 name:@"handleAdalRequest"
                                               object:nil];
}
-(void)unregisterForNotifications
{
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:@"handleAdalRequest"
                                                  object:nil];
}


-(void)viewDidUnload
{
    [self unregisterForNotifications];
}

/*** Your custom method called on notification ***/
-(void)yourCustomMethod:(NSNotification*)_notification
{
    AppDelegate *appDelegate = (AppDelegate*)[[UIApplication sharedApplication] delegate];
    NSString* upnInRequest = nil;
    BOOL isBrokerRequest = [ADBrokerContext isBrokerRequest:appDelegate._url
                                                  returnUpn:&upnInRequest];
    if(isBrokerRequest)
    {
        [self getAllAccounts];
        if(upnInRequest || users.count == 0)
        {
            [ADBrokerContext invokeBrokerForSourceApplication:[[appDelegate._url absoluteString] copy]
                                            sourceApplication:[appDelegate._sourceApplication copy]];
            
            appDelegate._url = nil;
            appDelegate._sourceApplication = nil;
            return;
        }
    }
}

-(void) viewWillAppear:(BOOL)animated
{
    [self getAllAccounts:YES];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

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
//    ViewController* __weak weakSelf = self;
//    id<ADTokenCacheStoring> cache = [[ADBrokerK]]
//    ADAuthenticationError *error = nil;
//    long count = (unsigned long)[[cache allItemsWithError:&error] count];
//    if (error)
//    {
//        return;
//    }
//    
//    [cache removeAllWithError:&error];
//    if (error)
//    {
//        return;
//    }
//    
//    cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore ;
//    count = (unsigned long)[[cache allItemsWithError:&error] count];
//    if (error)
//    {
//        return;
//    }
//    
//    [cache removeAllWithError:&error];
//    if (error)
//    {
//        return;
//    }
    
    ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:[ADBrokerSettings sharedInstance].authority];
    [ctx removeWorkPlaceJoinRegistration:nil];
    
    [self getAllAccounts:YES];
}


- (IBAction)addUserPressed:(id)sender
{
    ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:[ADBrokerSettings sharedInstance].authority];
    
    AppDelegate *appDelegate = (AppDelegate*)[[UIApplication sharedApplication] delegate];
    NSString* upnInRequest = nil;
    BOOL isBrokerRequest = [ADBrokerContext isBrokerRequest:appDelegate._url
                                                  returnUpn:&upnInRequest];
    if(isBrokerRequest)
    {
        [self getAllAccounts];
        [ADBrokerContext invokeBrokerForSourceApplication:[[appDelegate._url absoluteString] copy]
                                        sourceApplication:[appDelegate._sourceApplication copy]
                                                      upn:upnInRequest];
        
        appDelegate._url = nil;
        appDelegate._sourceApplication = nil;
    }
    else
    {
    [ctx acquireAccount:nil
        completionBlock:^(ADAuthenticationResult *result) {
        if(result.status != AD_SUCCEEDED)
        {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Error"
                                                            message:result.error.errorDetails
                                                           delegate:self
                                                  cancelButtonTitle:@"OK"
                                                  otherButtonTitles:nil];
            
            dispatch_async(dispatch_get_main_queue(),^{
            [alert show];
            });
        }
        else{
            [self getAllAccounts:YES];
        }
    }];
    }
}


- (IBAction)clearLogPressed:(id)sender
{
    [[CUTLibrary sharedLogger] clearLogs];
}


- (IBAction)emailLogPressed:(id)sender
{
    [[[CUTLibrary sharedLogger] getLogWriter] fetchLogDataWithCompletion:^(NSData *data, NSStringEncoding encoding, NSError *error) {
        if(!error)
        {
            dispatch_async(dispatch_get_main_queue(),^{
                mailComposer = [[MFMailComposeViewController alloc]init];
                mailComposer.mailComposeDelegate = self;
                [mailComposer setSubject:@"Authenticator Logs"];
                [mailComposer setMessageBody:@"attached:" isHTML:NO];
                [mailComposer addAttachmentData:data mimeType:@"text/plain" fileName:@"Authenticator-log.log"];
                [self presentViewController:mailComposer animated:YES completion:nil];
            });
        }
    }];
}

#pragma mark - mail compose delegate
-(void)mailComposeController:(MFMailComposeViewController *)controller
         didFinishWithResult:(MFMailComposeResult)result
                       error:(NSError *)error{
    
    if (result) {
        NSLog(@"Result : %d",result);
    }
    
    if (error) {
        NSLog(@"Error : %@",error);
    }
    
    [self dismissViewControllerAnimated:YES completion:nil];
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
        [ADBrokerContext invokeBrokerForSourceApplication:[[appDelegate._url absoluteString] copy]
                                        sourceApplication:[appDelegate._sourceApplication copy]
                                                      upn:info.getUpn];
        
        appDelegate._url = nil;
        appDelegate._sourceApplication = nil;
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

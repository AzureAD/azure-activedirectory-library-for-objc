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
#import <ADAuthenticationBroker/ADBrokerKeychainTokenCacheStore.h>
#import <ADALiOS/ADAuthenticationError.h>
#import <ADALiOS/ADUserInformation.h>
#import <ADALiOS/ADTokenCacheStoreItem.h>

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextView *resultLabel;
- (IBAction)pressMeAction:(id)sender;
- (IBAction)clearKeychainPressed:(id)sender;
- (IBAction)getUsersPressed:(id)sender;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

-(void) setStatus: (NSString*) status
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.resultLabel setText:status];
    });
}

- (IBAction)clearKeychainPressed:(id)sender
{
    
    ViewController* __weak weakSelf = self;
    ADBrokerKeychainTokenCacheStore* cache = [ADBrokerKeychainTokenCacheStore new];
    ADAuthenticationError *error = nil;
    long count = (unsigned long)[[cache allItemsWithError:&error] count];
    if (error)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    [weakSelf setStatus:[NSString stringWithFormat:@"Removing %lu items..", count]];

    [cache removeAllWithError:&error];
    if (error)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    [weakSelf setStatus:[NSString stringWithFormat:@"Current count %lu", (unsigned long)[[cache allItemsWithError:&error] count]]];
}

- (IBAction)getUsersPressed:(id)sender
{
ADAuthenticationError* error;
id<ADTokenCacheStoring> cache = [ADBrokerKeychainTokenCacheStore new];
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
@end

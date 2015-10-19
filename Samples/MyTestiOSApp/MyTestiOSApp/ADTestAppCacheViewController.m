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


#import "ADTestAppCacheViewController.h"

#import <ADALiOS/ADAL.h>
#import "ADTestAppSettings.h"
#import "ADTestAppLogger.h"

@interface ADTestAppCacheViewController ()

@property IBOutlet UITableView* cacheTable;

@end

@implementation ADTestAppCacheViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

- (IBAction)expireAllPressed:(id)sender
{
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [ADTestAppLogger logMessage:[NSString stringWithFormat:@"Expire All failed to retrieve allItems: %@", error.errorDetails]
                               type:TALogError];
        return;
    }
    for(ADTokenCacheStoreItem* item in array)
    {
        item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
        [cache addOrUpdateItem:item error:&error];
    }
    if (error)
    {
        [ADTestAppLogger logMessage:[NSString stringWithFormat:@"Expire All failed to update item: %@", error.errorDetails]
                               type:TALogError];
    }
    else
    {
        [ADTestAppLogger logMessage:@"Successfully expired all tokens." type:TALogSuccess];
    }
}

@end

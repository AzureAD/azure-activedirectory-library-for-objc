//
//  ADTestAppCacheViewController.m
//  MyTestiOSApp
//
//  Created by Ryan Pangrle on 8/6/15.
//  Copyright (c) 2015 Microsoft. All rights reserved.
//

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

//
//  ADTestAppProfileViewController.h
//  MyTestiOSApp
//
//  Created by Ryan Pangrle on 4/29/16.
//  Copyright © 2016 MS. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ADTestAppProfileViewController : UIViewController <UITableViewDelegate, UITableViewDataSource>

+ (NSString*)currentProfileTitle;
+ (ADTestAppProfileViewController*)sharedProfileViewController;

@end

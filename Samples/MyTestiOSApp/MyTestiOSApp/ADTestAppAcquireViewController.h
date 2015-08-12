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


#import "ADTestAppSettingsViewController.h"

@class ADTestAppSettings;

@interface ADTestAppAcquireViewController : UIViewController <UIPopoverControllerDelegate>
{
    IBOutlet UILabel*               _statusLabel;
    IBOutlet UITextField*           _tfUserId;
    IBOutlet UISegmentedControl*    _scUserType;
    IBOutlet UISegmentedControl*    _scPromptBehavior;
    
    ADTestAppSettings* _settings;
}

@property (strong, nonatomic) NSManagedObjectContext *managedObjectContext;

@property (strong, nonatomic) UIPopoverController *flipsidePopoverController;

@end

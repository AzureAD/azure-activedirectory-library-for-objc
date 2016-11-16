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


#import "ADAutoTextAndButtonView.h"

@interface ADAutoTextAndButtonView ()

@end

@implementation ADAutoTextAndButtonView

- (id)initWithFrame:(CGRect)frame{
    
    if (!(self = [super initWithFrame:frame]))
    {
        return nil;
    }
    
    [self loadView];
    
    return self;
}


- (void)loadView
{
    self.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.translatesAutoresizingMaskIntoConstraints = YES;
    self.autoresizesSubviews = NO;
    self.backgroundColor = UIColor.whiteColor;
    
    UITextView* textView = [[UITextView alloc] init];
    textView.autocorrectionType = UITextAutocorrectionTypeNo;
    textView.translatesAutoresizingMaskIntoConstraints = NO;
    textView.editable = YES;
    textView.layer.cornerRadius = 8.0;
    textView.layer.borderWidth = 1.0;
    textView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    
    _dataTextView = textView;
    
    UIButton* myButton = [[UIButton alloc] init];
    myButton.backgroundColor = UIColor.greenColor;
    myButton.titleLabel.textColor = UIColor.whiteColor;
    myButton.translatesAutoresizingMaskIntoConstraints = NO;
    
    _actionButton = myButton;
    [self addSubview:textView];
    [self addSubview:myButton];
    
    UILayoutGuide* margins = self.layoutMarginsGuide;
        [textView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor].active = YES;
        [textView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor].active = YES;
        [textView.bottomAnchor constraintEqualToAnchor:myButton.topAnchor constant:-8.0].active = YES;
        [myButton.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
        [myButton.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor].active = YES;
        [myButton.heightAnchor constraintEqualToConstant:20.0];
//        [textView.topAnchor constraintEqualToAnchor:self.superview.bottomAnchor constant:8.0].active = YES;
//        [myButton.bottomAnchor constraintEqualToAnchor:self.superview.topAnchor constant:-8.0].active = YES;
}

@end

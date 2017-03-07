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

#import "ADAutoTextAndButtonView.h"

@implementation ADAutoTextAndButtonView

- (id)initWithFrame:(CGRect)frame
{
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
    self.translatesAutoresizingMaskIntoConstraints = NO;
    self.autoresizesSubviews = NO;
    self.backgroundColor = UIColor.whiteColor;
    
    UITextView* textView = [[UITextView alloc] init];
    textView.autocorrectionType = UITextAutocorrectionTypeNo;
    textView.accessibilityIdentifier = @"requestInfo";
    textView.translatesAutoresizingMaskIntoConstraints = NO;
    textView.editable = YES;
    textView.layer.cornerRadius = 8.0;
    textView.layer.borderWidth = 1.0;
    textView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    
    _textView = textView;
    
    UIButton* goButton = [[UIButton alloc] init];
    [goButton setTitle:@"Go" forState:UIControlStateNormal];
    goButton.backgroundColor = UIColor.greenColor;
    goButton.titleLabel.textColor = UIColor.whiteColor;
    goButton.translatesAutoresizingMaskIntoConstraints = NO;
    goButton.accessibilityIdentifier = @"requestGo";
    _actionButton = goButton;
    
    [self addSubview:textView];
    [self addSubview:goButton];
    
    
    NSDictionary* views = @{@"textView" : textView, @"actionButton" : goButton };
    NSArray* veritcalConstraints =
    [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[textView]-[actionButton]|"
                                            options:0
                                            metrics:NULL
                                              views:views];
    NSArray* horizConstraints1 =
    [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[textView]|"
                                            options:0
                                            metrics:nil
                                              views:views];
    
    NSArray* horizConstraints2 =
    [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[actionButton]|"
                                            options:0
                                            metrics:nil
                                              views:views];
    
    [self addConstraints:veritcalConstraints];
    [self addConstraints:horizConstraints1];
    [self addConstraints:horizConstraints2];
}

/*
// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect {
    // Drawing code
}
*/

@end

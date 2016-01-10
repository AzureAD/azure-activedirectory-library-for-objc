#import <objc/runtime.h>
#import "ADAuthenticationBroker.h"
#import "ADALFrameworkUtils.h"

@implementation UIAlertView (Additions)

static const char *HANDLER_KEY = "com.microsoft.adal.alertviewHandler";

static UIAlertView *alert;

+ (void)presentCredentialAlert:(void (^)(NSUInteger))handler {
    
    NSBundle* bundle = [ADALFrameworkUtils frameworkBundle];
    if (!bundle)
    {
        bundle = [NSBundle mainBundle];
    }
    
    alert = [[UIAlertView alloc] initWithTitle:NSLocalizedStringFromTableInBundle(@"Enter your credentials", nil, bundle, nil)
                                       message:nil
                                      delegate:nil
                             cancelButtonTitle:NSLocalizedStringFromTableInBundle(@"Cancel", nil, bundle, nil)
                             otherButtonTitles: nil];
    
    alert.alertViewStyle = UIAlertViewStyleLoginAndPasswordInput;
    [alert addButtonWithTitle:NSLocalizedStringFromTableInBundle(@"Login", nil, bundle, nil)];
    [alert setDelegate:alert];
    
    if (handler)
        objc_setAssociatedObject(alert, HANDLER_KEY, handler, OBJC_ASSOCIATION_COPY_NONATOMIC);
    
    dispatch_async(dispatch_get_main_queue(), ^(void){
        [alert show];
    });
}

- (void)alertView:(UIAlertView *)alertView didDismissWithButtonIndex:(NSInteger)buttonIndex {
    id handler = objc_getAssociatedObject(alertView, HANDLER_KEY);
    
    if (handler)
        ((void(^)())handler)(buttonIndex);
}

+ (id) getAlertInstance
{
    return alert;
}

@end
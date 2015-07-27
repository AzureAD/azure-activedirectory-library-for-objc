#import <UIKit/UIKit.h>

#if !TARGET_OS_WATCH

@interface UIAlertView (Additions)

+ (void)presentCredentialAlert:(void(^)(NSUInteger index))handler;

+ (id) getAlertInstance;
@end

#endif
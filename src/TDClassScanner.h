#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const TDScannerErrorDomain;

typedef NS_ENUM(NSInteger, TDScannerError) {
    TDScannerErrorUnknownBundleID = 1,
    TDScannerErrorSpawnFailed     = 2,
    TDScannerErrorTaskForPID      = 3,
    TDScannerErrorDyldRead        = 4,
    TDScannerErrorSignaturesLoad  = 5,
};

NSArray * _Nullable TDLoadSignatures(NSString *path, NSError **error);

NSArray<NSDictionary *> * _Nullable TDListInstalledUserApps(void);

NSDictionary * _Nullable TDScanBundleID(NSString *bundleID,
                                        NSArray *compiledSignatures,
                                        NSError **error);

NS_ASSUME_NONNULL_END

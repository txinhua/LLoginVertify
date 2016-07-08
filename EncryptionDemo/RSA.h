//
//  RSA.h
//  EncryptionDemo
//
//  Created by VcaiTech on 16/7/8.
//  Copyright © 2016年 VcaiTech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSA : NSObject

+ (NSString *)encryptString:(NSString *)str;
+ (NSString *)encryptData:(NSData *)data;

+ (NSString *)decryptString:(NSString *)str ;
+ (NSString *)decryptData:(NSData *)data ;


@end

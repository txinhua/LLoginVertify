//
//  ViewController.m
//  EncryptionDemo
//
//  Created by VcaiTech on 16/7/7.
//  Copyright © 2016年 VcaiTech. All rights reserved.
//

#import "ViewController.h"
#import "CryptorTools.h"
#import "RSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    //test code
//    CryptorTools *tool = [[CryptorTools alloc] init];
//    NSString *pubPath = [[NSBundle mainBundle] pathForResource:@"rsa_cert.der" ofType:nil];
//    [tool loadPublicKeyWithFilePath:pubPath];
//    NSString *privatePath = [[NSBundle mainBundle] pathForResource:@"p.p12" ofType:nil];
//    [tool loadPrivateKey:privatePath password:@"vcadmin"];
//    
//    NSString *result = [tool RSAEncryptString:@"xiaoer"];
//    NSLog(@"%@",result);
//    NSLog(@"%@", [tool RSADecryptString:result]);
    // Do any additional setup after loading the view, typically from a nib.

    NSString *name = [RSA encryptString:@"你的账号"];
    NSString *password = [RSA encryptString:@"你的密码"];
    NSLog(@"%@",name);
    NSLog(@"%@",password);
    
//    NSLog(@"%@", [tool RSADecryptString:name]);
//    NSLog(@"%@", [tool RSADecryptString:password]);
    NSLog(@"%@", [RSA decryptString:name]);
    NSLog(@"%@", [RSA decryptString:password]);
    
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end

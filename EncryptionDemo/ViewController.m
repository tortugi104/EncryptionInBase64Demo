//
//  ViewController.m
//  EncryptionDemo
//
//  Created by Sakshi on 14/05/18.
//  Copyright © 2018 Sakshi. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "NSData+Base64.h"
#import "StringEncryption.h"

#define KServiceKey @"0366D8637F9C6B21"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    //To Encode
    NSString *stringInBase64 = [self encryptString:@"STRING YOU WANT TO ENCODE"];
    NSLog(@"%@",stringInBase64);

    //To decode
    NSString *decodedString = [self decryptString:stringInBase64];
    NSLog(@"%@",decodedString);
}



#pragma mark - Encryption/Decryption
-(NSString *)encryptString:(NSString *)_secret
{
    NSData *_secretData = [_secret dataUsingEncoding:NSUTF8StringEncoding];
    CCOptions padding = kCCOptionPKCS7Padding;
    
    StringEncryption *crypto = [[StringEncryption alloc] init];
    NSData *encryptedData = [crypto encrypt:_secretData key:[KServiceKey dataUsingEncoding:NSUTF8StringEncoding] padding:&padding];
    NSString *finalEncrypt = [encryptedData base64EncodingWithLineLength:0];
    [self decryptString:finalEncrypt];
    return finalEncrypt;
}

-(NSString *)decryptString:(NSString *)finalEncrypt
{
    CCOptions padding = kCCOptionPKCS7Padding;
    NSData *dataToDecrypt = [NSData dataWithBase64EncodedString:finalEncrypt];
    
    StringEncryption *crypto = [[StringEncryption alloc] init];
    NSData *decryptedData = [crypto decrypt:dataToDecrypt key:[KServiceKey dataUsingEncoding:NSUTF8StringEncoding] padding:&padding];
    NSString *strData = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    return strData;
}



@end

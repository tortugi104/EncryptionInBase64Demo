//
//  ViewController.m
//  EncryptionDemo
//
//  Created by Sakshi on 14/05/18.
//  Copyright © 2018 Sakshi. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    //To Encode
    NSString *stringInBase64 = [self encodeStringTo64:@"STRING YOU WANT TO ENCODE"];
    
    //To decode
    NSString *decodedString = [self decodeString:stringInBase64];
    NSLog(@"%@",decodedString);
}


//Encoding
- (NSString *)encodeStringTo64:(NSString *)stringToBeEncoded {
    return [stringToBeEncoded stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
}

//Decoding
-(NSString *)decodeString:(NSString *)stringToBeDecoded {
    NSString *result = [stringToBeDecoded stringByReplacingOccurrencesOfString:@"+" withString:@" "];
    result = [result stringByRemovingPercentEncoding];
    return result;
}





@end

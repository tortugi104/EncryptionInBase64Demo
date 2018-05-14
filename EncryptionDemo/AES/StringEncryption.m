//
//  StringEncryption.m
//
//  Created by DAVID VEKSLER on 2/4/09.
//

#import "StringEncryption.h"
#import "NSData+Base64.h"

#if DEBUG
#define LOGGING_FACILITY(X, Y)	\
NSAssert(X, Y);	

#define LOGGING_FACILITY1(X, Y, Z)	\
NSAssert1(X, Y, Z);	
#else
#define LOGGING_FACILITY(X, Y)	\
if(!(X)) {			\
// NSLog(Y);		\
exit(-1);		\
}					

#define LOGGING_FACILITY1(X, Y, Z)	\
if(!(X)) {				\
// NSLog(Y, Z);		\
exit(-1);			\
}						
#endif

@implementation StringEncryption

NSString *_key = @"1234567891123456";
CCOptions padding = kCCOptionPKCS7Padding;

+ (NSString *) EncryptString:(NSString *)plainSourceStringToEncrypt
{
StringEncryption *crypto = [[StringEncryption alloc] init] ;
		
	NSData *_secretData = [plainSourceStringToEncrypt dataUsingEncoding:NSASCIIStringEncoding];
		
	// You can use md5 to make sure key is 16 bits long
	NSData *encryptedData = [crypto encrypt:_secretData key:[_key dataUsingEncoding:NSUTF8StringEncoding] padding:&padding];
		
	return [encryptedData base64EncodingWithLineLength:0];	
}


+ (NSString *)DecryptString:(NSString *)base64StringToDecrypt
{
	StringEncryption *crypto = [[StringEncryption alloc] init];
	NSData *data = [crypto decrypt:[base64StringToDecrypt dataUsingEncoding:NSUTF8StringEncoding] key:[_key dataUsingEncoding:NSUTF8StringEncoding] padding: &padding];
	
	return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSData *)encrypt:(NSData *)plainText key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7
{
    return [self doCipher:plainText key:aSymmetricKey context:kCCEncrypt padding:pkcs7];
}

- (NSData *)decrypt:(NSData *)plainText key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7
{
    return [self doCipher:plainText key:aSymmetricKey context:kCCDecrypt padding:pkcs7];
}

- (NSData *)doCipher:(NSData *)plainText key:(NSData *)aSymmetricKey
			 context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7
{
    CCCryptorStatus ccStatus = kCCSuccess;
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    // A friendly helper pointer.
    uint8_t * ptr;
	
    // Initialization vector; dummy in this case 0's.
    uint8_t iv[kChosenCipherBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
	
    plainTextBufferSize = [plainText length];
	
    //LOGGING_FACILITY(plainTextBufferSize > 0, @"Empty plaintext passed in." );
	
    // We don't want to toss padding on if we don't need to
    if(encryptOrDecrypt == kCCEncrypt) {
        if(*pkcs7 != kCCOptionECBMode) {
            if((plainTextBufferSize % kChosenCipherBlockSize) == 0) {
                *pkcs7 = kCCOptionPKCS7Padding;
            } else {
                *pkcs7 = kCCOptionPKCS7Padding;
            }
        }
    }
    else if(encryptOrDecrypt != kCCDecrypt)
    {
    }
	
    // Create and Initialize the crypto reference.
    CCCryptorCreate(encryptOrDecrypt,
                               kCCAlgorithmAES128,
                               *pkcs7,
                               (const void *)[aSymmetricKey bytes],
                               kChosenCipherKeySize,
                               (const void *)iv,
                               &thisEncipher
                               );
	
   //LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem creating the context, ccStatus == %d.", ccStatus );
	
    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);
	
    // Allocate buffer.
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );
	
    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
	
    // Initialize some necessary book keeping.
	
    ptr = bufferPtr;
	
    // Set up initial size.
    remainingBytes = bufferPtrSize;
	
    // Actually perform the encryption or decryption.
    CCCryptorUpdate(thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );
	
   //LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with CCCryptorUpdate, ccStatus == %d.", ccStatus );
	
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
	
    /* From CommonCryptor.h:
	 
     @enum      CCCryptorStatus
     @abstract  Return values from CommonCryptor operations.
	 
     @constant  kCCSuccess          Operation completed normally.
     @constant  kCCParamError       Illegal parameter value.
     @constant  kCCBufferTooSmall   Insufficent buffer provided for specified operation.
     @constant  kCCMemoryFailure    Memory allocation failure.
     @constant  kCCAlignmentError   Input size was not aligned properly.
     @constant  kCCDecodeError      Input data did not decode or decrypt properly.
     @constant  kCCUnimplemented    Function not implemented for the current algorithm.
	 
     enum {
	 kCCSuccess          = 0,
	 kCCParamError       = -4300,
	 kCCBufferTooSmall   = -4301,
	 kCCMemoryFailure    = -4302,
	 kCCAlignmentError   = -4303,
	 kCCDecodeError      = -4304,
	 kCCUnimplemented    = -4305
	 };
	 typedef int32_t CCCryptorStatus;
	 */
	
    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );
	
    totalBytesWritten += movedBytes;
	
    if(thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }
	
    //LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with encipherment ccStatus == %d", ccStatus );
	
    if (ccStatus == kCCSuccess)
        cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    else
        cipherOrPlainText = nil;
	
    if(bufferPtr) free(bufferPtr);
	
    return cipherOrPlainText;
	
    /*
     Or the corresponding one-shot call:
	 
     ccStatus = CCCrypt(    encryptOrDecrypt,
     kCCAlgorithmAES128,
     typeOfSymmetricOpts,
     (const void *)[self getSymmetricKeyBytes],
     kChosenCipherKeySize,
     iv,
     (const void *) [plainText bytes],
     plainTextBufferSize,
     (void *)bufferPtr,
     bufferPtrSize,
     &movedBytes
     );
     */
}
@end

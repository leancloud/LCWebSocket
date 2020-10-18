//
//  LCWebSocketClient.m
//  LCWebSocket
//
//  Created by pzheng on 2020/10/18.
//

#import "LCWebSocketClient.h"

#import <Security/SecRandom.h>
#import <CommonCrypto/CommonDigest.h>

@interface LCWebSocketConnectionClosure : NSObject

@property (nonatomic) LCWebSocketCloseCode closeCode;
@property (nonatomic) NSString *reason;
@property (nonatomic) NSDictionary<NSErrorUserInfoKey, id> *userInfo;

@end

@implementation LCWebSocketConnectionClosure

- (NSError *)error
{
    NSDictionary *userInfo = self.userInfo;
    if (self.reason) {
        NSMutableDictionary *mutableDictionary = ([userInfo mutableCopy]
                                                  ?: [NSMutableDictionary dictionary]);
        mutableDictionary[NSLocalizedFailureReasonErrorKey] = self.reason;
        userInfo = mutableDictionary;
    }
    return [NSError errorWithDomain:@"LCWebSocketErrorDomain"
                               code:self.closeCode
                           userInfo:userInfo];
}

@end

@implementation LCWebSocketMessage

+ (instancetype)messageWithData:(NSData *)data
{
    return [[self alloc] initWithData:data];
}

+ (instancetype)messageWithString:(NSString *)string
{
    return [[self alloc] initWithString:string];
}

- (instancetype)initWithData:(NSData *)data
{
    self = [super init];
    if (self) {
        _type = LCWebSocketMessageTypeData;
        _data = data;
    }
    return self;
}

- (instancetype)initWithString:(NSString *)string
{
    self = [super init];
    if (self) {
        _type = LCWebSocketMessageTypeString;
        _string = string;
    }
    return self;
}

@end

typedef NS_ENUM(UInt8, LCWebSocketOpcode) {
    LCWebSocketOpcodeContinuation = 0x0,
    LCWebSocketOpcodeText = 0x1,
    LCWebSocketOpcodeBinary = 0x2,
    LCWebSocketOpcodeConnectionClose = 0x8,
    LCWebSocketOpcodePing = 0x9,
    LCWebSocketOpcodePong = 0xA,
};

@interface LCWebSocketFrame : NSObject

@property (nonatomic) BOOL isFIN;
@property (nonatomic) LCWebSocketOpcode opcode;
/// Only for input data frame, means the size of the WebSocket data frame.
@property (nonatomic) NSUInteger totalSize;
/// If the frame is output data, it means all data of the WebSocket data frame;
/// If the frame is input data, it means the payload of the WebSocket data frame;
@property (nonatomic) NSData *payload;
/// The following two only for output data frame.
@property (nonatomic) NSUInteger offset;
@property (nonatomic) void(^completion)(void);

@end

@implementation LCWebSocketFrame

static const UInt8 LCWebSocketFrameBitMaskFIN = 0x80;
static const UInt8 LCWebSocketFrameBitMaskRSV = 0x70;
static const UInt8 LCWebSocketFrameBitMaskOpcode = 0x0F;
static const UInt8 LCWebSocketFrameBitMaskMask = 0x80;
static const UInt8 LCWebSocketFrameBitMaskPayloadLength = 0x7F;

#if LC_WEBSOCKET_DEBUG
- (void)dealloc
{
    NSLog(@"[DEBUG] %@ - dealloc", NSStringFromClass([self class]));
}
#endif

+ (LCWebSocketFrame *)frameFrom:(UInt8 *)buffer
                         length:(NSUInteger)bufferLength
              connectionClosure:(LCWebSocketConnectionClosure * __autoreleasing *)ccPtr
{
    // FIN
    BOOL isFIN = (buffer[0] & LCWebSocketFrameBitMaskFIN);
    // RSV
    if ((buffer[0] & LCWebSocketFrameBitMaskRSV) != 0) {
        *ccPtr = [self protocolError:@"a nonzero RSV value is received"];
        return nil;
    }
    // Opcode
    UInt8 opcode = (buffer[0] & LCWebSocketFrameBitMaskOpcode);
    BOOL isControlFrame = (opcode >= LCWebSocketOpcodeConnectionClose
                           && opcode <= LCWebSocketOpcodePong);
    if (opcode > LCWebSocketOpcodeBinary && !isControlFrame) {
        *ccPtr = [self protocolError:@"an unknown opcode is received"];
        return nil;
    } else if (isControlFrame && !isFIN) {
        *ccPtr = [self protocolError:@"all control frames must not be fragmented"];
        return nil;
    }
    // Mask
    if ((buffer[1] & LCWebSocketFrameBitMaskMask) != 0) {
        *ccPtr = [self protocolError:@"detects a masked frame from server"];
        return nil;
    }
    // Payload length
    NSUInteger payloadLength = (NSUInteger)(buffer[1] & LCWebSocketFrameBitMaskPayloadLength);
    if (isControlFrame && payloadLength > 125) {
        *ccPtr = [self protocolError:@"all control frames must have a payload length of 125 bytes or less"];
        return nil;
    }
    NSUInteger offset = 2;
    if (payloadLength == 126 && bufferLength >= 4) {
        payloadLength = (NSUInteger)([self readUInt16:buffer offset:offset]);
        offset += 2;
    } else if (payloadLength == 127 && bufferLength >= 10) {
        payloadLength = (NSUInteger)([self readUInt64:buffer offset:offset]);
        offset += 8;
    }
    NSUInteger totalSize = offset + payloadLength;
    if (bufferLength < totalSize) {
        // need more data
        return nil;
    }
    buffer = buffer + offset;  // move pointer to payload
    if (opcode == LCWebSocketOpcodeConnectionClose) {
        LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
        closure.closeCode = LCWebSocketCloseCodeNoStatusReceived;
        if (payloadLength > 1) {
            NSInteger closeCode = (NSInteger)([self readUInt16:buffer offset:0]);
            if (closeCode > 999 && closeCode < 5000) {
                closure.closeCode = closeCode;
            }
            if (payloadLength > 2) {
                NSData *data = [NSData dataWithBytes:buffer + 2
                                              length:payloadLength - 2];
                closure.reason = [[NSString alloc] initWithData:data
                                                       encoding:NSUTF8StringEncoding];
            }
        }
        *ccPtr = closure;
        return nil;
    }
    LCWebSocketFrame *frame = [LCWebSocketFrame new];
    frame.isFIN = isFIN;
    frame.opcode = opcode;
    frame.totalSize = totalSize;
    frame.payload = [NSData dataWithBytes:buffer
                                   length:payloadLength];
    return frame;
}

+ (LCWebSocketFrame *)frameFrom:(NSData *)data
                         opcode:(LCWebSocketOpcode)opcode
{
    UInt8 payloadLen;
    NSUInteger bufferLength = 6 + data.length;
    UInt16 payloadLen16 = 0;
    UInt64 payloadLen64 = 0;
    if (data.length < 126) {
        payloadLen = (UInt8)(data.length);
    } else if (data.length <= UINT16_MAX) {
        payloadLen = 126;
        bufferLength += 2;
        payloadLen16 = (UInt16)(data.length);
    } else {
        payloadLen = 127;
        bufferLength += 8;
        payloadLen64 = (UInt64)(data.length);
    }
    UInt8 buffer[bufferLength];
    buffer[0] = LCWebSocketFrameBitMaskFIN | opcode;
    buffer[1] = LCWebSocketFrameBitMaskMask | payloadLen;
    NSUInteger offset = 2;
    if (payloadLen16 > 0) {
        [self writeUInt16:payloadLen16 buffer:buffer offset:offset];
        offset += 2;
    } else if (payloadLen64 > 0) {
        [self writeUInt64:payloadLen64 buffer:buffer offset:offset];
        offset += 8;
    }
    UInt8 *maskingKey = buffer + offset;
    __unused int status = SecRandomCopyBytes(kSecRandomDefault, 4, maskingKey);
    offset += 4;
    for (NSUInteger i = 0; i < data.length; i++) {
        buffer[offset + i] = ((UInt8 *)(data.bytes))[i] ^ maskingKey[i % 4];
    }
    LCWebSocketFrame *frame = [LCWebSocketFrame new];
    frame.opcode = opcode;
    frame.payload = [NSData dataWithBytes:buffer
                                   length:bufferLength];
    frame.offset = 0;
    return frame;
}

+ (LCWebSocketFrame *)frameFrom:(LCWebSocketMessage *)message
{
    NSData *data;
    LCWebSocketOpcode opcode;
    if (message.type == LCWebSocketMessageTypeData) {
        data = message.data;
        opcode = LCWebSocketOpcodeBinary;
    } else {
        data = [message.string dataUsingEncoding:NSUTF8StringEncoding];
        opcode = LCWebSocketOpcodeText;
    }
    return [self frameFrom:data
                    opcode:opcode];
}

+ (UInt16)readUInt16:(UInt8 *)buffer offset:(NSUInteger)offset
{
    return ((UInt16)(buffer[offset + 0]) << 8) | (UInt16)(buffer[offset + 1]);
}

+ (UInt64)readUInt64:(UInt8 *)buffer offset:(NSUInteger)offset
{
    UInt64 value = (0 | (UInt64)(buffer[offset]));
    for (int i = 1; i < 8; i++) {
        value = ((value << 8) | (UInt64)(buffer[offset + i]));
    }
    return value;
}

+ (void)writeUInt16:(UInt16)value buffer:(UInt8 *)buffer offset:(NSUInteger)offset
{
    buffer[offset] = (UInt8)(value >> 8);
    buffer[offset + 1] = (UInt8)(value & 0xFF);
}

+ (void)writeUInt64:(UInt64)value buffer:(UInt8 *)buffer offset:(NSUInteger)offset
{
    for (int i = 0; i < 8; i++) {
        buffer[offset + i] = (UInt8)((value >> (8 * (7 - i))) & 0xFF);
    }
}

+ (LCWebSocketConnectionClosure *)protocolError:(NSString *)reason
{
    LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
    closure.closeCode = LCWebSocketCloseCodeProtocolError;
    closure.reason = reason;
    return closure;
}

@end

@interface LCWebSocket () <NSStreamDelegate>

@property (nonatomic) BOOL isOpened;
@property (nonatomic) BOOL isWritable;
@property (nonatomic) dispatch_queue_t readQueue;
@property (nonatomic) dispatch_queue_t writeQueue;
@property (nonatomic) NSInputStream *inputStream;
@property (nonatomic) NSOutputStream *outputStream;
@property (nonatomic) NSMutableData *inputSegmentBuffer;
@property (nonatomic) NSMutableArray<LCWebSocketFrame *> *inputFrameStack;
@property (nonatomic) NSMutableArray<LCWebSocketFrame *> *outputFrameQueue;

@end

@implementation LCWebSocket

- (instancetype)init
{
    self = [super init];
    if (self) {
        _delegateQueue = dispatch_get_main_queue();
        _isOpened = false;
        _isWritable = false;
        _readQueue = dispatch_queue_create([NSString stringWithFormat:
                                            @"%@.readQueue",
                                            NSStringFromClass([self class])
                                            ].UTF8String,
                                           NULL);
        _writeQueue = dispatch_queue_create([NSString stringWithFormat:
                                             @"%@.writeQueue",
                                             NSStringFromClass([self class])
                                             ].UTF8String,
                                            NULL);
#if LC_WEBSOCKET_DEBUG
        dispatch_queue_set_specific(_readQueue,
                                    (__bridge void *)_readQueue,
                                    (__bridge void *)_readQueue,
                                    NULL);
        dispatch_queue_set_specific(_writeQueue,
                                    (__bridge void *)_writeQueue,
                                    (__bridge void *)_writeQueue,
                                    NULL);
#endif
        _inputFrameStack = [NSMutableArray array];
        _outputFrameQueue = [NSMutableArray array];
    }
    return self;
}

- (instancetype)initWithURL:(NSURL *)url
{
    self = [self init];
    if (self) {
        _request = [NSMutableURLRequest requestWithURL:url];
        [_request setValue:@"websocket" forHTTPHeaderField:@"Upgrade"];
        [_request setValue:@"Upgrade" forHTTPHeaderField:@"Connection"];
        NSString *origin = url.absoluteString;
        NSURL *hostURL = [NSURL URLWithString:@"/" relativeToURL:url];
        if (hostURL) {
            origin = hostURL.absoluteString;
            if (origin.length > 0) {
                origin = [origin substringToIndex:origin.length - 1];
            }
        }
        [_request setValue:origin forHTTPHeaderField:@"Origin"];
        [_request setValue:@"13" forHTTPHeaderField:@"Sec-WebSocket-Version"];
    }
    return self;
}

- (instancetype)initWithURL:(NSURL *)url
                  protocols:(NSArray<NSString *> *)protocols
{
    self = [self initWithURL:url];
    if (self) {
        if (protocols.count > 0) {
            [_request setValue:[protocols componentsJoinedByString:@", "]
            forHTTPHeaderField:@"Sec-WebSocket-Protocol"];
        }
    }
    return self;
}

- (instancetype)initWithRequest:(NSURLRequest *)request
{
    self = [self init];
    if (self) {
        _request = [request mutableCopy];
    }
    return self;
}

#if LC_WEBSOCKET_DEBUG
- (void)dealloc
{
    NSLog(@"[DEBUG] %@ - dealloc", NSStringFromClass([self class]));
}
#endif

- (BOOL)assertSpecificReadQueue
{
#if LC_WEBSOCKET_DEBUG
    void *specificKey = (__bridge void *)(self.readQueue);
    return dispatch_get_specific(specificKey) == specificKey;
#else
    return true;
#endif
}

- (BOOL)assertSpecificWriteQueue
{
#if LC_WEBSOCKET_DEBUG
    void *specificKey = (__bridge void *)(self.writeQueue);
    return dispatch_get_specific(specificKey) == specificKey;
#else
    return true;
#endif
}

- (void)open
{
    NSAssert(self.inputStream == nil &&
             self.outputStream == nil,
             @"should NOT reopen");
    NSURL *url = self.request.URL;
    if (!url.host) {
        LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
        closure.closeCode = LCWebSocketCloseCodeInvalid;
        closure.reason = @"Invalid request";
        closure.userInfo = @{
            @"URL": url ?: @"nil",
        };
        [self notifyCloseWithError:[closure error]];
        return;
    }
    BOOL isTLS = [LCWebSocket isTLS:url];
    NSNumber *port = url.port;
    if (!port) {
        port = isTLS ? @443 : @80;
    }
    NSString *hostWithPort = [NSString stringWithFormat:@"%@:%@", url.host, port];
    if (!self.request.allHTTPHeaderFields[@"Host"]) {
        [self.request setValue:hostWithPort
            forHTTPHeaderField:@"Host"];
    }
    [self.request setValue:[LCWebSocket generateSecWebSocketKey]
        forHTTPHeaderField:@"Sec-WebSocket-Key"];
    CFReadStreamRef readStreamRef;
    CFWriteStreamRef writeStreamRef;
    CFStreamCreatePairWithSocketToHost(NULL,
                                       (__bridge CFStringRef)(url.host),
                                       port.unsignedIntValue,
                                       &readStreamRef,
                                       &writeStreamRef);
    self.inputStream = (__bridge_transfer NSInputStream *)readStreamRef;
    self.outputStream = (__bridge_transfer NSOutputStream *)writeStreamRef;
    if (!self.inputStream ||
        !self.outputStream) {
        LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
        closure.closeCode = LCWebSocketCloseCodeInvalid;
        closure.reason = @"Creating sockets failed";
        closure.userInfo = @{
            @"host:port": hostWithPort,
        };
        [self notifyCloseWithError:[closure error]];
        return;
    }
    CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)(self.inputStream),
                                 self.readQueue);
    CFWriteStreamSetDispatchQueue((__bridge CFWriteStreamRef)(self.outputStream),
                                  self.writeQueue);
    self.inputStream.delegate = self;
    self.outputStream.delegate = self;
    if (isTLS) {
        [self.inputStream setProperty:NSStreamSocketSecurityLevelNegotiatedSSL
                               forKey:NSStreamSocketSecurityLevelKey];
        [self.outputStream setProperty:NSStreamSocketSecurityLevelNegotiatedSSL
                                forKey:NSStreamSocketSecurityLevelKey];
        if (self.sslSettings) {
            CFReadStreamSetProperty((__bridge CFReadStreamRef)(self.inputStream),
                                    kCFStreamPropertySSLSettings,
                                    (__bridge CFTypeRef)(self.sslSettings));
            CFWriteStreamSetProperty((__bridge CFWriteStreamRef)(self.outputStream),
                                     kCFStreamPropertySSLSettings,
                                     (__bridge CFTypeRef)(self.sslSettings));
        }
    }
    [self.inputStream open];
    [self.outputStream open];
    __weak typeof(self) ws = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 NSEC_PER_SEC * (self.request.timeoutInterval ?: 60.0)),
                   self.readQueue, ^{
        LCWebSocket *ss = ws;
        if (!ss) {
            return;
        }
        if (!ss.isOpened) {
            LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
            closure.closeCode = LCWebSocketCloseCodeInvalid;
            closure.reason = @"Opening sockets timeout";
            closure.userInfo = @{
                @"host:port": hostWithPort,
            };
            [ss notifyCloseWithError:[closure error]];
            [ss purgeInputResourceInCurrentQueue:true];
            [ss purgeOutputResourceInCurrentQueue:false];
            return;
        }
    });
}

- (void)sendMessage:(LCWebSocketMessage *)message
         completion:(void (^)(void))completion
{
    dispatch_async(self.writeQueue, ^{
        if (!self.isWritable) {
            return;
        }
        LCWebSocketFrame *frame = [LCWebSocketFrame frameFrom:message];
        frame.completion = completion;
        [self.outputFrameQueue addObject:frame];
        [self dequeueFrames];
    });
}

- (void)closeWithCloseCode:(LCWebSocketCloseCode)closeCode
                    reason:(NSData *)reason
{
    NSUInteger bufferLength = 2;
    UInt8 buffer[bufferLength];
    [LCWebSocketFrame writeUInt16:(UInt16)closeCode
                           buffer:buffer
                           offset:0];
    NSMutableData *data = [NSMutableData dataWithBytes:buffer
                                                length:bufferLength];
    if (reason) {
        [data appendData:reason];
    }
    [self sendControlFrames:LCWebSocketOpcodeConnectionClose
                       data:data
                 completion:nil];
}

- (void)sendPing:(NSData *)data
      completion:(void (^)(void))completion
{
    [self sendControlFrames:LCWebSocketOpcodePing
                       data:data
                 completion:completion];
}

- (void)sendPong:(NSData *)data
      completion:(void (^)(void))completion
{
    [self sendControlFrames:LCWebSocketOpcodePong
                       data:data
                 completion:completion];
}

- (void)sendControlFrames:(LCWebSocketOpcode)opcode
                     data:(NSData *)data
               completion:(void (^)(void))completion
{
    dispatch_async(self.writeQueue, ^{
        if (!self.isWritable) {
            return;
        }
        if (opcode == LCWebSocketOpcodeConnectionClose) {
            self.isWritable = false;
        }
        LCWebSocketFrame *frame = [LCWebSocketFrame frameFrom:(data ?: [NSData data])
                                                       opcode:opcode];
        frame.completion = completion;
        NSUInteger index = (self.outputFrameQueue.firstObject.offset > 0) ? 1 : 0;
        [self.outputFrameQueue insertObject:frame
                                    atIndex:index];
        [self dequeueFrames];
    });
}

// MARK: NSStreamDelegate

- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
    switch (eventCode) {
        case NSStreamEventOpenCompleted:
            [self handleStreamEventOpenCompleted:aStream];
            break;
        case NSStreamEventHasBytesAvailable:
            [self handleStreamEventHasBytesAvailable:aStream];
            break;
        case NSStreamEventHasSpaceAvailable:
            [self handleStreamEventHasSpaceAvailable:aStream];
            break;
        case NSStreamEventErrorOccurred:
            [self handleStreamEventErrorOccurred:aStream];
            break;
        case NSStreamEventEndEncountered:
            [self handleStreamEventEndEncountered:aStream];
            break;
        default:
            break;
    }
}

- (void)handleStreamEventOpenCompleted:(NSStream *)aStream
{
    if (aStream != self.outputStream) {
        return;
    }
    LCWebSocketFrame *request = [LCWebSocketFrame new];
    request.payload = [LCWebSocket generateHTTPRequestData:self.request];
    request.offset = 0;
    [self.outputFrameQueue addObject:request];
    [self dequeueFrames];
}

- (void)handleStreamEventHasBytesAvailable:(NSStream *)aStream
{
    if (aStream != self.inputStream) {
        return;
    }
    NSParameterAssert([self assertSpecificReadQueue]);
    NSUInteger bufferMax = (1024 * 32) + 1;
    UInt8 bufferArray[bufferMax];
    NSInteger readBytes = [self.inputStream read:bufferArray
                                       maxLength:bufferMax];
    if (readBytes < 1) {
        return;
    }
    UInt8 *buffer = bufferArray;
    NSUInteger bufferLength = (NSUInteger)readBytes;
    if (self.inputSegmentBuffer) {
        [self.inputSegmentBuffer appendBytes:buffer
                                      length:bufferLength];
        buffer = (UInt8 *)(self.inputSegmentBuffer.bytes);
        bufferLength = self.inputSegmentBuffer.length;
    }
    NSUInteger restBufferLength;
    if (self.isOpened) {
        restBufferLength = [self processDataFrames:buffer
                                            length:bufferLength];
    } else {
        restBufferLength = [self processHandshake:buffer
                                           length:bufferLength];
    }
    if (restBufferLength == 0) {
        self.inputSegmentBuffer = nil;
    } else if (restBufferLength != (self.inputSegmentBuffer
                                    ? self.inputSegmentBuffer.length
                                    : 0)) {
        self.inputSegmentBuffer = [NSMutableData dataWithBytes:buffer + bufferLength - restBufferLength
                                                        length:restBufferLength];;
    }
}

- (void)handleStreamEventHasSpaceAvailable:(NSStream *)aStream
{
    if (aStream != self.outputStream) {
        return;
    }
    [self dequeueFrames];
}

- (void)handleStreamEventErrorOccurred:(NSStream *)aStream
{
    NSError *error = aStream.streamError;
    NSDictionary *userInfo;
    if (error) {
        userInfo = @{
            NSUnderlyingErrorKey: error,
        };
    }
    [self purgeInputResourceInCurrentQueue:(aStream == self.inputStream)];
    [self purgeOutputResourceInCurrentQueue:(aStream == self.outputStream)];
    LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
    closure.closeCode = LCWebSocketCloseCodeAbnormalClosure;
    closure.reason = @"Error Occurred";
    closure.userInfo = userInfo;
    [self notifyCloseWithError:[closure error]];
}

- (void)handleStreamEventEndEncountered:(NSStream *)aStream
{
    BOOL isInputStream = (aStream == self.inputStream);
    [self purgeInputResourceInCurrentQueue:isInputStream];
    if (isInputStream) {
        [self closeWithCloseCode:LCWebSocketCloseCodeNormalClosure
                          reason:nil];
    } else {
        [self purgeOutputResourceInCurrentQueue:true];
    }
    LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
    closure.closeCode = LCWebSocketCloseCodeInternalServerError;
    closure.reason = @"End Encountered";
    closure.userInfo = @{
        @"stream": (isInputStream ? @"input" : @"output"),
    };
    [self notifyCloseWithError:[closure error]];
}

// MARK: Process Data

- (NSUInteger)processHandshake:(UInt8 *)buffer
                        length:(NSUInteger)bufferLength
{
    NSParameterAssert([self assertSpecificReadQueue]);
    UInt8 CRLFBytes[] = { '\r', '\n', '\r', '\n' };
    NSInteger k = 0;
    CFIndex httpResponseSize = 0;
    for (int i = 0; i < bufferLength; i++) {
        if (buffer[i] == CRLFBytes[k]) {
            k += 1;
            if (k == 4) {
                httpResponseSize = i + 1;
                break;
            }
        } else {
            k = 0;
        }
    }
    if (httpResponseSize == 0) {
        return bufferLength;
    }
    CFHTTPMessageRef messageRef = CFHTTPMessageCreateEmpty(NULL, FALSE);
    CFHTTPMessageAppendBytes(messageRef, buffer, httpResponseSize);
    CFIndex statusCode = CFHTTPMessageGetResponseStatusCode(messageRef);
    NSString *upgrade = (__bridge_transfer NSString *)({
        CFHTTPMessageCopyHeaderFieldValue(messageRef, CFSTR("Upgrade"));
    });
    NSString *connection = (__bridge_transfer NSString *)({
        CFHTTPMessageCopyHeaderFieldValue(messageRef, CFSTR("Connection"));
    });
    NSString *secWebSocketAccept = [(__bridge_transfer NSString *)({
        CFHTTPMessageCopyHeaderFieldValue(messageRef, CFSTR("Sec-WebSocket-Accept"));
    }) stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *secWebSocketKey = self.request.allHTTPHeaderFields[@"Sec-WebSocket-Key"];
    NSString *requestSecWebSocketProtocol = self.request.allHTTPHeaderFields[@"Sec-WebSocket-Protocol"];
    NSString *responseSecWebSocketProtocol = (__bridge_transfer NSString *)({
        CFHTTPMessageCopyHeaderFieldValue(messageRef, CFSTR("Sec-WebSocket-Protocol"));
    });
    CFRelease(messageRef);
    if (statusCode != 101) {
        [self purgeInputResourceInCurrentQueue:true];
        [self purgeOutputResourceInCurrentQueue:false];
        LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
        closure.closeCode = statusCode;
        closure.reason = @"Upgrade failed, status code is not `101`.";
        closure.userInfo = @{
            @"statusCode": @(statusCode),
        };
        [self notifyCloseWithError:[closure error]];
        return 0;
    }
    if ([upgrade caseInsensitiveCompare:@"websocket"] != NSOrderedSame
        || [connection caseInsensitiveCompare:@"upgrade"] != NSOrderedSame
        || ![LCWebSocket validateSecWebSocketAccept:secWebSocketAccept
                                    secWebSocketKey:secWebSocketKey]
        || ![LCWebSocket validateSecWebSocketProtocol:requestSecWebSocketProtocol
                                     responseProtocol:responseSecWebSocketProtocol]) {
        [self purgeInputResourceInCurrentQueue:true];
        [self purgeOutputResourceInCurrentQueue:false];
        LCWebSocketConnectionClosure *closure = [LCWebSocketConnectionClosure new];
        closure.closeCode = LCWebSocketCloseCodeInvalid;
        closure.reason = @"Upgrade failed, response headers invalid.";
        closure.userInfo = @{
            @"Upgrade": (upgrade ?: @"nil"),
            @"Connection": (connection ?: @"nil"),
            @"Sec-WebSocket-Accept": (secWebSocketAccept ?: @"nil"),
            @"Sec-WebSocket-Key": (secWebSocketKey ?: @"nil"),
            @"Request-Sec-WebSocket-Protocol": (requestSecWebSocketProtocol ?: @"nil"),
            @"Response-Sec-WebSocket-Protocol": (responseSecWebSocketProtocol ?: @"nil"),
        };
        [self notifyCloseWithError:[closure error]];
        return 0;
    }
    self.isOpened = true;
    dispatch_async(self.writeQueue, ^{
        self.isWritable = true;
    });
    dispatch_async(self.delegateQueue, ^{
        [self.delegate LCWebSocket:self
               didOpenWithProtocol:responseSecWebSocketProtocol];
    });
    return [self processDataFrames:buffer + httpResponseSize
                            length:bufferLength - httpResponseSize];
}

- (NSUInteger)processDataFrames:(UInt8 *)buffer
                         length:(NSUInteger)bufferLength
{
    NSParameterAssert([self assertSpecificReadQueue]);
    if (bufferLength < 2) {
        return bufferLength;
    }
    LCWebSocketConnectionClosure *closure;
    LCWebSocketFrame *frame = [LCWebSocketFrame frameFrom:buffer
                                                   length:bufferLength
                                        connectionClosure:&closure];
    if (closure) {
        if (closure.closeCode == LCWebSocketCloseCodeProtocolError) {
            [self closeWithCloseCode:closure.closeCode
                              reason:nil];
        } else {
            [self closeWithCloseCode:LCWebSocketCloseCodeNormalClosure
                              reason:nil];
        }
        [self notifyCloseWithError:[closure error]];
        return 0;
    }
    if (!frame) {
        return bufferLength;
    }
    NSUInteger offset = frame.totalSize;
    if (frame.isFIN) {
        if (frame.opcode == LCWebSocketOpcodeBinary ||
            frame.opcode == LCWebSocketOpcodeText ||
            frame.opcode == LCWebSocketOpcodeContinuation) {
            if (frame.opcode == LCWebSocketOpcodeContinuation) {
                if (self.inputFrameStack.count > 0) {
                    [self.inputFrameStack addObject:frame];
                    LCWebSocketFrame *completeFrame = [LCWebSocketFrame new];
                    completeFrame.opcode = self.inputFrameStack.firstObject.opcode;
                    NSMutableData *payload = [NSMutableData data];
                    for (LCWebSocketFrame *item in self.inputFrameStack) {
                        [payload appendData:item.payload];
                    }
                    completeFrame.payload = payload;
                    frame = completeFrame;
                    [self.inputFrameStack removeAllObjects];
                } else {
                    closure = [LCWebSocketConnectionClosure new];
                    closure.closeCode = LCWebSocketCloseCodeProtocolError;
                    closure.reason = @"Message fragments NOT be sent in the order by server.";
                    [self closeWithCloseCode:closure.closeCode
                                      reason:nil];
                    [self notifyCloseWithError:[closure error]];
                    return 0;
                }
            }
            LCWebSocketMessage *message;
            if (frame.opcode == LCWebSocketOpcodeBinary) {
                message = [LCWebSocketMessage messageWithData:frame.payload];
            } else {
                message = [LCWebSocketMessage
                           messageWithString:[[NSString alloc]
                                              initWithData:frame.payload
                                              encoding:NSUTF8StringEncoding]];
            }
            dispatch_async(self.delegateQueue, ^{
                [self.delegate LCWebSocket:self
                         didReceiveMessage:message];
            });
        } else if (frame.opcode == LCWebSocketOpcodePong) {
            dispatch_async(self.delegateQueue, ^{
                [self.delegate LCWebSocket:self
                            didReceivePong:frame.payload];
            });
        } else if (frame.opcode == LCWebSocketOpcodePing) {
            dispatch_async(self.delegateQueue, ^{
                [self.delegate LCWebSocket:self
                            didReceivePing:frame.payload];
            });
        }
    } else {
        if ((self.inputFrameStack.count > 0 &&
             frame.opcode == LCWebSocketOpcodeContinuation) ||
            (self.inputFrameStack.count == 0 &&
             (frame.opcode == LCWebSocketOpcodeBinary ||
              frame.opcode == LCWebSocketOpcodeText))) {
            [self.inputFrameStack addObject:frame];
        } else {
            closure = [LCWebSocketConnectionClosure new];
            closure.closeCode = LCWebSocketCloseCodeProtocolError;
            closure.reason = @"Message fragments NOT be sent in the order by server.";
            [self closeWithCloseCode:closure.closeCode
                              reason:nil];
            [self notifyCloseWithError:[closure error]];
            return 0;
        }
    }
    return [self processDataFrames:buffer + offset
                            length:bufferLength - offset];
}

- (void)dequeueFrames
{
    NSParameterAssert([self assertSpecificWriteQueue]);
    LCWebSocketFrame *frame = self.outputFrameQueue.firstObject;
    if (!frame) {
        return;
    }
    NSInteger writtenBytes = [self.outputStream write:(UInt8 *)(frame.payload.bytes) + frame.offset
                                            maxLength:frame.payload.length - frame.offset];
    if (writtenBytes < 1) {
        return;
    }
    frame.offset += (NSUInteger)writtenBytes;
    if (frame.offset == frame.payload.length) {
        if (frame.completion) {
            dispatch_async(self.delegateQueue, ^{
                frame.completion();
                frame.completion = nil;
            });
        }
        if (frame.opcode == LCWebSocketOpcodeConnectionClose) {
            [self purgeOutputResourceInCurrentQueue:true];
        } else {
            [self.outputFrameQueue removeObjectAtIndex:0];
        }
    }
}

// MARK: Misc

+ (BOOL)isTLS:(NSURL *)url
{
    NSString *scheme = url.scheme;
    return ((scheme.length > 0) &&
            [@[@"wss", @"https"] containsObject:scheme.lowercaseString]);
}

+ (NSString *)generateSecWebSocketKey
{
    NSMutableData *bytes = [[NSMutableData alloc] initWithLength:16];
    if (SecRandomCopyBytes(kSecRandomDefault, bytes.length, bytes.mutableBytes) == errSecSuccess) {
        return [bytes base64EncodedStringWithOptions:0];
    } else {
        NSInteger seed = 16;
        NSMutableString *string = [NSMutableString stringWithCapacity:seed];
        for (int i = 0; i < seed; i++) {
            [string appendFormat:@"%C", (unichar)(97 + arc4random_uniform(25))];
        }
        return [[string dataUsingEncoding:NSUTF8StringEncoding]
                base64EncodedStringWithOptions:0];
    }
}

+ (BOOL)validateSecWebSocketAccept:(NSString *)value
                   secWebSocketKey:(NSString *)key
{
    if (!value.length ||
        !key.length) {
        return false;
    }
    NSData *data = [[key stringByAppendingString:@"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"]
                    dataUsingEncoding:NSUTF8StringEncoding];
    UInt8 digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    return [[[NSData dataWithBytes:digest
                            length:CC_SHA1_DIGEST_LENGTH]
             base64EncodedStringWithOptions:0]
            isEqualToString:value];
}

+ (BOOL)validateSecWebSocketProtocol:(NSString *)requestProtocol
                    responseProtocol:(NSString *)responseProtocol
{
    NSMutableSet<NSString *> *requestProtocolSet = [NSMutableSet set];
    if (requestProtocol.length > 0) {
        NSArray<NSString *> *requestProtocolArray = [requestProtocol componentsSeparatedByString:@","];
        for (NSString *item in requestProtocolArray) {
            [requestProtocolSet addObject:
             [item stringByTrimmingCharactersInSet:
              [NSCharacterSet whitespaceCharacterSet]]];
        }
    }
    if (responseProtocol.length > 0) {
        NSArray<NSString *> *responseProtocolArray = [responseProtocol componentsSeparatedByString:@","];
        for (NSString *item in responseProtocolArray) {
            if (![requestProtocolSet containsObject:
                  [item stringByTrimmingCharactersInSet:
                   [NSCharacterSet whitespaceCharacterSet]]]) {
                return false;
            }
        }
    }
    return true;
}

+ (NSData *)generateHTTPRequestData:(NSURLRequest *)request
{
    CFHTTPMessageRef messageRef = CFHTTPMessageCreateRequest(NULL,
                                                             CFSTR("GET"),
                                                             (__bridge CFURLRef)(request.URL),
                                                             kCFHTTPVersion1_1);
    for (NSString *key in request.allHTTPHeaderFields) {
        NSString *value = request.allHTTPHeaderFields[key];
        CFHTTPMessageSetHeaderFieldValue(messageRef,
                                         (__bridge CFStringRef)key,
                                         (__bridge CFStringRef)value);
    }
    if (request.HTTPBody) {
        CFHTTPMessageSetBody(messageRef,
                             (__bridge CFDataRef)(request.HTTPBody));
    }
    NSData *data = (__bridge_transfer NSData *)CFHTTPMessageCopySerializedMessage(messageRef);
    CFRelease(messageRef);
    return data;
}

- (void)notifyCloseWithError:(NSError *)error
{
    dispatch_async(self.delegateQueue, ^{
        [self.delegate LCWebSocket:self
                 didCloseWithError:error];
    });
}

- (void)clean
{
    [self purgeInputResourceInCurrentQueue:false];
    [self purgeOutputResourceInCurrentQueue:false];
}

- (void)purgeInputResourceInCurrentQueue:(BOOL)inCurrentQueue
{
    void(^purge)(void) = ^(void) {
        NSParameterAssert([self assertSpecificReadQueue]);
        self.isOpened = false;
        if (self.inputStream.delegate) {
            self.inputStream.delegate = nil;
            CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)(self.inputStream),
                                         NULL);
            [self.inputStream close];
        }
        self.inputSegmentBuffer = nil;
        [self.inputFrameStack removeAllObjects];
    };
    if (inCurrentQueue) {
        purge();
    } else {
        dispatch_async(self.readQueue, ^{
            purge();
        });
    }
}

- (void)purgeOutputResourceInCurrentQueue:(BOOL)inCurrentQueue
{
    void(^purge)(void) = ^(void) {
        NSParameterAssert([self assertSpecificWriteQueue]);
        self.isWritable = false;
        if (self.outputStream.delegate) {
            self.outputStream.delegate = nil;
            CFWriteStreamSetDispatchQueue((__bridge CFWriteStreamRef)(self.outputStream),
                                          NULL);
            [self.outputStream close];
        }
        [self.outputFrameQueue removeAllObjects];
    };
    if (inCurrentQueue) {
        purge();
    } else {
        dispatch_async(self.writeQueue, ^{
            purge();
        });
    }
}

@end

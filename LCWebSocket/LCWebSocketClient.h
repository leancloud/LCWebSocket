//
//  LCWebSocketClient.h
//  LCWebSocket
//
//  Created by pzheng on 2020/10/18.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, LCWebSocketCloseCode)
{
    LCWebSocketCloseCodeInvalid =                             0,
    LCWebSocketCloseCodeNormalClosure =                    1000,
    LCWebSocketCloseCodeGoingAway =                        1001,
    LCWebSocketCloseCodeProtocolError =                    1002,
    LCWebSocketCloseCodeUnsupportedData =                  1003,
    LCWebSocketCloseCodeNoStatusReceived =                 1005,
    LCWebSocketCloseCodeAbnormalClosure =                  1006,
    LCWebSocketCloseCodeInvalidFramePayloadData =          1007,
    LCWebSocketCloseCodePolicyViolation =                  1008,
    LCWebSocketCloseCodeMessageTooBig =                    1009,
    LCWebSocketCloseCodeMandatoryExtensionMissing =        1010,
    LCWebSocketCloseCodeInternalServerError =              1011,
    LCWebSocketCloseCodeTLSHandshakeFailure =              1015,
};

typedef NS_ENUM(NSInteger, LCWebSocketMessageType) {
    LCWebSocketMessageTypeData = 0,
    LCWebSocketMessageTypeString = 1,
};

NS_ASSUME_NONNULL_BEGIN

@interface LCWebSocketMessage : NSObject

+ (instancetype)messageWithData:(NSData *)data;
+ (instancetype)messageWithString:(NSString *)string;

- (instancetype)initWithData:(NSData *)data NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithString:(NSString *)string NS_DESIGNATED_INITIALIZER;

@property (nonatomic, readonly) LCWebSocketMessageType type;
@property (nonatomic, nullable, readonly) NSData *data;
@property (nonatomic, nullable, readonly) NSString *string;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

@class LCWebSocket;

@protocol LCWebSocketDelegate <NSObject>

- (void)LCWebSocket:(LCWebSocket *)socket didOpenWithProtocol:(NSString * _Nullable)protocol;

- (void)LCWebSocket:(LCWebSocket *)socket didCloseWithError:(NSError *)error;

- (void)LCWebSocket:(LCWebSocket *)socket didReceiveMessage:(LCWebSocketMessage *)message;

- (void)LCWebSocket:(LCWebSocket *)socket didReceivePing:(NSData * _Nullable)data;

- (void)LCWebSocket:(LCWebSocket *)socket didReceivePong:(NSData * _Nullable)data;

@end

@interface LCWebSocket : NSObject

- (instancetype)initWithURL:(NSURL *)url;
- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray<NSString *> *)protocols;
- (instancetype)initWithRequest:(NSURLRequest *)request;

@property (nonatomic, nullable, weak) id<LCWebSocketDelegate> delegate;
@property (nonatomic) dispatch_queue_t delegateQueue;
@property (nonatomic) NSMutableURLRequest *request;
@property (nonatomic, nullable) id sslSettings;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (void)open;
- (void)closeWithCloseCode:(LCWebSocketCloseCode)closeCode reason:(NSData * _Nullable)reason;

- (void)sendMessage:(LCWebSocketMessage *)message completion:(void (^ _Nullable)(void))completion;
- (void)sendPing:(NSData * _Nullable)data completion:(void (^ _Nullable)(void))completion;
- (void)sendPong:(NSData * _Nullable)data completion:(void (^ _Nullable)(void))completion;

- (void)clean;

@end

NS_ASSUME_NONNULL_END

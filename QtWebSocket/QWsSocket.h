#ifndef QWSSOCKET_H
#define QWSSOCKET_H

#include <QAbstractSocket>
#include <QTcpSocket>
#include <QTime>

class QWsSocket : public QAbstractSocket
{
	Q_OBJECT

public:
	enum EOpcode
	{
		OpContinue = 0x0,
		OpText = 0x1,
		OpBinary = 0x2,
		OpReserved1 = 0x3,
		OpReserved2 = 0x4,
		OpReserved3 = 0x5,
		OpReserved4 = 0x6,
		OpReserved5 = 0x7,
		OpControl = 0x8,
		OpClose = 0x8,
		OpPing = 0x9,
		OpPong = 0xA,
		OpReserved6 = 0xB,
		OpReserved7 = 0xC,
		OpReserved8 = 0xD,
		OpReserved9 = 0xE,
		OpReserved10 = 0xF
	};

	enum StatusCode
	{
		NormalClosure = 1000,
		GoingAway = 1001,
		ProtocolError = 1002,
		UnsupportedDataType = 1003,
		ReservedStatus1004 = 1004,
		ReservedStatus1005 = 1005,
		ReservedStatus1006 = 1006,
		DataInconsistent = 1007,
		PolicyViolated = 1008,
		MessageTooBig = 1009,
		RequiredExtensionUnsupported = 1010, // Is not sent by server
		InternalServerError = 1011, // Is not sent by client
		ReservedStatus1012 = 1012,
		ReservedStatus1013 = 1013,
		ReservedStatus1014 = 1014,
		ReservedStatus1015 = 1015,

		StandardStatusReserveStart = 1000,
		StandardStatusReserveEnd = 2999,
		FrameworkStatusReserveStart = 3000,
		FrameworkStatusReserveEnd = 3999,
		VendorStatusReserveStart = 4000,
		VendorStatusReserveEnd = 4999
	};

    typedef enum {
        binary = 0,
        text = 1
    } MessageType;

    typedef struct {
        QByteArray data;
        MessageType type;
    } SocketMessage;

public:
	// ctor
	QWsSocket(QTcpSocket * socket = 0, QObject * parent = 0);
	// dtor
	virtual ~QWsSocket();

    // Public methods
    qint64 write ( const SocketMessage &message, int maxFrameBytes = 0 ) ;

public slots:
	virtual void close(quint16 status = NormalClosure, const QString & reason = QString());
	void ping();

signals:
    void frameReceived(QWsSocket::SocketMessage frame);
	void pong(quint64 elapsedTime);

protected:
	qint64 writeFrames ( QList<QByteArray> framesList );
	qint64 writeFrame ( const QByteArray & byteArray );

protected slots:
	void dataReceived();

private slots:
	// private func
	void tcpSocketAboutToClose();
	void tcpSocketDisconnected();

private:
    typedef struct {
        quint8 working[6];
        qint32 working_len;
        qint32 unichars_so_far;
        qint32 bytes_so_far;
        qint32 expecting_continuation;
    } DecoderState;

private:
	void handleControlOpcode(const QByteArray & data);
	void handleClose(const QByteArray & data);
	void handleMessage();

    int validate(QByteArray a);
    int validate_partial(QByteArray a);

    DecoderState newDecoderState();
    int process_byte(quint8 incoming, DecoderState *state, bool do_nothing = false);
    int end_processing(DecoderState state);

private:
	enum EState
	{
		HeaderPending,
		PayloadLengthPending,
		BigPayloadLenghPending,
		MaskPending,
		PayloadBodyPending
	};

    enum {
        OK = 0,                         /* No error */
        MISSING_CONTINUATION = 1,       /* A multibyte sequence without as many continuation bytes as expected.  e.g. [ef 81] 48 */
        UNEXPECTED_CONTINUATION = 2,    /* A continuation byte when not expected */
        OVERLONG_FORM = 3,              /* A full multibyte sequence encoding something that should have been encoded shorter */
        OUT_OF_RANGE = 4,               /* A full multibyte sequence encoding something larger than 10FFFF */
        BAD_SCALAR_VALUE = 5,           /* A full multibyte sequence encoding something in the range U+D800..U+DFFF */
        INVALID = 6                     /* bytes 0xFE or 0xFF */
    };

private:
	// private vars
	QTcpSocket * tcpSocket;
	QByteArray currentFrame;
	QTime pingTimer;

	EState state;
	EOpcode frameOpcode;
	EOpcode messageOpcode;
	bool isFinalFragment;
	bool hasMask;
	quint64 payloadLength;
	QByteArray maskingKey;
    SocketMessage message;

public:
	// Static functions
	static QByteArray generateMaskingKey();
	static QByteArray mask( QByteArray data, QByteArray maskingKey );
	static QList<QByteArray> composeFrames( QByteArray byteArray, bool asBinary = false, int maxFrameBytes = 0 );
	static QByteArray composeHeader( bool fin, EOpcode frameOpcode, quint64 payloadLength, QByteArray maskingKey = QByteArray() );
	static QString composeOpeningHandShake( QString ressourceName, QString host, QString origin, QString extensions, QString key );

	// static vars
	static int maxBytesPerFrame;
};

#endif // QWSSOCKET_H

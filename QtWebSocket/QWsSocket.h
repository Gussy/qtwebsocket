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

public:
	// ctor
	QWsSocket(QTcpSocket * socket = 0, QObject * parent = 0);
	// dtor
	virtual ~QWsSocket();

	// Public methods
	qint64 write ( const QString & string, int maxFrameBytes = 0 ); // write data as text
	qint64 write ( const QByteArray & byteArray, int maxFrameBytes = 0 ); // write data as binary

public slots:
	virtual void close(quint16 status = NormalClosure, const QString & reason = QString());
	void ping();

signals:
	void frameReceived(QString frame);
	void frameReceived(QByteArray frame);
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
	void handleControlOpcode(const QByteArray & data);
	void handleClose(const QByteArray & data);
	void handleMessage();

    static QString fromUtf8(const char * str, int size, bool *ok = 0);

private:
	enum EState
	{
		HeaderPending,
		PayloadLengthPending,
		BigPayloadLenghPending,
		MaskPending,
		PayloadBodyPending
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

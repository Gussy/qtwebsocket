#include "QWsServer.h"

#include <QRegExp>
#include <QStringList>
#include <QByteArray>
#include <QCryptographicHash>

const QString QWsServer::regExpResourceNameStr( "GET\\s(.*)\\sHTTP/1.1\r\n" );
const QString QWsServer::regExpHostStr( "Host:\\s(.+:\\d+)\r\n" );
const QString QWsServer::regExpKeyStr( "Sec-WebSocket-Key:\\s(.{24})\r\n" );
const QString QWsServer::regExpVersionStr( "Sec-WebSocket-Version:\\s(\\d)\r\n" );
const QString QWsServer::regExpOriginStr( "Sec-WebSocket-Origin:\\s(.+)\r\n" );
const QString QWsServer::regExpProtocolStr( "Sec-WebSocket-Protocol:\\s(.+)\r\n" );
const QString QWsServer::regExpExtensionsStr( "Sec-WebSocket-Extensions:\\s(.+)\r\n" );

QWsServer::QWsServer(QObject * parent)
	: QTcpServer(parent)
{
	tcpServer = new QTcpServer(this);
	connect(tcpServer, SIGNAL(newConnection()), this, SLOT(newTcpConnection()));
}

QWsServer::~QWsServer()
{
	tcpServer->deleteLater();
}

bool QWsServer::listen(const QHostAddress & address, quint16 port)
{
	bool launched = tcpServer->listen(address, port);

	if ( ! launched )
		treatSocketError();

	return launched;
}

void QWsServer::close()
{
	tcpServer->close();
}

void QWsServer::treatSocketError()
{
	serverSocketError = tcpServer->serverError();
	serverSocketErrorString = tcpServer->errorString();
}

QAbstractSocket::SocketError QWsServer::serverError()
{
	return serverSocketError;
}

QString QWsServer::errorString()
{
	return serverSocketErrorString;
}

void QWsServer::newTcpConnection()
{
	QTcpSocket * clientSocket = tcpServer->nextPendingConnection();

	QObject * clientObject = qobject_cast<QObject*>(clientSocket);

	connect(clientObject, SIGNAL(readyRead()), this, SLOT(dataReceived()));
}

void QWsServer::dataReceived()
{
	QTcpSocket * clientSocket = qobject_cast<QTcpSocket*>(sender());
	if (clientSocket == 0)
		return;

	QString request( clientSocket->readAll() );

	QRegExp regExp;
	regExp.setMinimal( true );
	
	// Extract mandatory datas
	// Resource name
	regExp.setPattern( QWsServer::regExpResourceNameStr );
	regExp.indexIn(request);
	QString resourceName = regExp.cap(1);
	
	// Host (address & port)
	regExp.setPattern( QWsServer::regExpHostStr );
	regExp.indexIn(request);
	QStringList sl = regExp.cap(1).split(':');
	QString hostPort;
	if ( sl.size() > 1 )
		hostPort = sl[1];
	QString hostAddress = sl[0];
	
	// Key
	regExp.setPattern( QWsServer::regExpKeyStr );
	regExp.indexIn(request);
	QString key = regExp.cap(1);
	
	// Version
	regExp.setPattern( QWsServer::regExpVersionStr );
	regExp.indexIn(request);
	QString version = regExp.cap(1);
	
	// Extract optional datas
	// Origin
	regExp.setPattern( QWsServer::regExpOriginStr );
	regExp.indexIn(request);
	QString origin = regExp.cap(1);

	// Protocol
	regExp.setPattern( QWsServer::regExpProtocolStr );
	regExp.indexIn(request);
	QString protocol = regExp.cap(1);

	// Extensions
	regExp.setPattern( QWsServer::regExpExtensionsStr );
	regExp.indexIn(request);
	QString extensions = regExp.cap(1);

	// If the mandatory params are not setted, we abord the handshake
	if ( hostAddress.isEmpty()
		|| hostPort.isEmpty()
		|| resourceName.isEmpty()
		|| key.isEmpty()
		|| version != "8" )
		return;

	// Compose handshake answer
	QString accept = computeAcceptV8( key );
	
	QString answer("HTTP/1.1 101 Switching Protocols\r\n");
	answer.append("Upgrade: websocket\r\n");
	answer.append("Connection: Upgrade\r\n");
	answer.append("Sec-WebSocket-Accept: " + accept + "\r\n");
	answer.append("\r\n");

	// Send handshake answer
	clientSocket->write( answer.toUtf8() );

	// Handshake OK, new connection
	int socketDescriptor = clientSocket->socketDescriptor();
	incomingConnection( socketDescriptor );
}

QString QWsServer::computeAcceptV8(QString key)
{
	key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	QByteArray hash = QCryptographicHash::hash ( key.toUtf8(), QCryptographicHash::Sha1 );
	return hash.toBase64();
}

void QWsServer::addPendingConnection( QTcpSocket * socket )
{
	if ( pendingConnections.size() < maxPendingConnections() )
		pendingConnections.enqueue(socket);
}

void QWsServer::incomingConnection( int socketDescriptor )
{
	//QWsSocket * socket = new QWsSocket(this); // FOR NEXT STEP
	QTcpSocket * socket = new QTcpSocket(tcpServer);
	socket->setSocketDescriptor( socketDescriptor/*, QAbstractSocket::ConnectedState*/ );
	
	addPendingConnection( socket );

	emit QWsServer::newConnection();
}

bool QWsServer::hasPendingConnections()
{
	if ( pendingConnections.size() > 0 )
		return true;
	return false;
}

QTcpSocket * QWsServer::nextPendingConnection()
{
	return pendingConnections.dequeue();
}
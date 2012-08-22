#include "ServerExample.h"

#include "Log.h"

ServerExample::ServerExample()
{
	int port = 1337;
    server = new QWsServer(this);
	if ( ! server->listen(QHostAddress::Any, port) )
	{
		Log::display( "Error: Can't launch server" );
		QMessageBox::critical(0, "QWsServer error", server->errorString());
	}
	else
	{
		Log::display( "Server is listening port " + QString::number(port) );
	}
	connect(server, SIGNAL(newConnection()), this, SLOT(onClientConnection()));
}

ServerExample::~ServerExample()
{
}

void ServerExample::onClientConnection()
{
	QWsSocket * clientSocket = server->nextPendingConnection();

	QObject * clientObject = qobject_cast<QObject*>(clientSocket);

    connect(clientObject, SIGNAL(frameReceived(QWsSocket::SocketMessage)), this, SLOT(onDataReceived(QWsSocket::SocketMessage)));
	connect(clientObject, SIGNAL(disconnected()), this, SLOT(onClientDisconnection()));
	connect(clientObject, SIGNAL(pong(quint64)), this, SLOT(onPong(quint64)));

	clients << clientSocket;

	Log::display("Client connected");
}

void ServerExample::onDataReceived(const QWsSocket::SocketMessage &message)
{
	QWsSocket * socket = qobject_cast<QWsSocket*>( sender() );
	if (socket == 0)
		return;

    Log::display( message.data.constData() );
	
	QWsSocket * client;
	foreach ( client, clients )
	{
        client->write( message );
	}
}

void ServerExample::onPong(quint64 elapsedTime)
{
	Log::display( "ping: " + QString::number(elapsedTime) + " ms" );
}

void ServerExample::onClientDisconnection()
{
	QWsSocket * socket = qobject_cast<QWsSocket*>(sender());
	if (socket == 0)
		return;

	clients.removeOne(socket);

	socket->deleteLater();

	Log::display("Client disconnected");
}

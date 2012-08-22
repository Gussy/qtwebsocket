#ifndef TESTSERVER_H
#define TESTSERVER_H

#include <QObject>
#include <QByteArray>
#include <QList>
#include "QWsSocket.h"

class QWsServer;
class QWsSocket;

class TestServer : public QObject
{
	Q_OBJECT

public:
	TestServer();
	~TestServer();

public slots:
	void onClientConnection();
    void onDataReceived(const QWsSocket::SocketMessage &message);
	void onPong(quint64 elapsedTime);
	void onClientDisconnection();

private:
	QWsServer * server;
	QList<QWsSocket*> clients;
};

#endif

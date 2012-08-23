#include "QWsSocket.h"

#include <QtEndian>
#include <QTextCodec>

int QWsSocket::maxBytesPerFrame = 1400;

QWsSocket::QWsSocket(QTcpSocket * socket, QObject * parent) :
	QAbstractSocket( QAbstractSocket::UnknownSocketType, parent ),
	tcpSocket(socket),
	state(HeaderPending),
	frameOpcode(OpContinue),
	messageOpcode(OpContinue),
	isFinalFragment(false),
	hasMask(false),
	payloadLength(0),
    maskingKey(4, 0)
{
	//setSocketState( QAbstractSocket::UnconnectedState );
	setSocketState( socket->state() );

	connect( tcpSocket, SIGNAL(readyRead()), this, SLOT(dataReceived()) );
	// XXX: Consider connecting socket's signals to own signals directly
	connect( tcpSocket, SIGNAL(disconnected()), this, SLOT(tcpSocketDisconnected()) );
	connect( tcpSocket, SIGNAL(aboutToClose()), this, SLOT(tcpSocketAboutToClose()) );

}

QWsSocket::~QWsSocket()
{
}

void QWsSocket::dataReceived()
{
	while (tcpSocket->state() == QAbstractSocket::ConnectedState)
	switch (state) {
	case HeaderPending: {
		if (tcpSocket->bytesAvailable() < 2)
			return;

		// FIN, RSV1-3, Opcode
		char header[2];
		tcpSocket->read(header, 2); // XXX: Handle return value
		isFinalFragment = (header[0] & 0x80) != 0;
		if ((header[0] & 0x70) != 0) // Check for RSV
		{
			// Since we don't support extensions yet
			// and also informed client about that
			// by omiting Sec-WebSocket-Extensions
			// header in handshake response
			// We MUST fail connection if any of RSV bits is set
			// as per http://tools.ietf.org/html/rfc6455#section-5.2
			close(ProtocolError);
			break;
		}
		frameOpcode = static_cast<EOpcode>(header[0] & 0x0F);

		if (!(frameOpcode & OpControl))
		{
			// See http://tools.ietf.org/html/rfc6455#section-5.4
			// for framing rules
			if (messageOpcode == OpContinue)
			{
				// Starting frame of a message
				messageOpcode = frameOpcode;
				if (messageOpcode == OpContinue)
				{
					// Message cannot start with a continuation opcode
					close(ProtocolError);
					break;
				}
			}
			else
			{
				if (frameOpcode != OpContinue)
				{
					// Non-starting message frames MUST
					// come with a continuation opcode
					close(ProtocolError);
					break;
				}
			}
		}

		// Mask, PayloadLength
		hasMask = (header[1] & 0x80) != 0;
		// As per http://tools.ietf.org/html/rfc6455#section-5.1
		// client MUST always mask its frames.
		if (!hasMask)
		{
			close(ProtocolError);
			break;
		}
		quint8 length = (header[1] & 0x7F);

		switch (length) {
		case 126:
			state = PayloadLengthPending;
			break;
		case 127:
			state = BigPayloadLenghPending;
			break;
		default:
			payloadLength = length;
			state = MaskPending;
			break;
		}
	}; break;
	case PayloadLengthPending: {
		if (tcpSocket->bytesAvailable() < 2)
			return;

		uchar length[2];
		tcpSocket->read(reinterpret_cast<char *>(length), 2); // XXX: Handle return value
		payloadLength = qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(length));
		state = MaskPending;
	}; break;
	case BigPayloadLenghPending: {
		if (tcpSocket->bytesAvailable() < 8)
			return;

		uchar length[8];
		tcpSocket->read(reinterpret_cast<char *>(length), 8); // XXX: Handle return value
		// Most significant bit must be set to 0 as per http://tools.ietf.org/html/rfc6455#section-5.2
		// XXX: Check for that?
		payloadLength = qFromBigEndian<quint64>(length) & ~(1L << 63);
		state = MaskPending;
	}; break;
	case MaskPending: {
		if (!hasMask) {
			state = PayloadBodyPending;
			break;
		}

		if (tcpSocket->bytesAvailable() < 4)
			return;

		tcpSocket->read(maskingKey.data(), 4); // XXX: Handle return value
		state = PayloadBodyPending;
	}; /* Intentional fall-through */
	case PayloadBodyPending: {
		// TODO: Handle large payloads
		if (tcpSocket->bytesAvailable() < static_cast<qint32>(payloadLength))
			return;

		state = HeaderPending;

		// Extension // UNSUPPORTED FOR NOW
        QByteArray ApplicationData = tcpSocket->read( payloadLength );
		if ( hasMask )
			ApplicationData = QWsSocket::mask( ApplicationData, maskingKey );

		if (frameOpcode & OpControl)
		{
			handleControlOpcode(ApplicationData);
			break;
		}
		currentFrame.append( ApplicationData );

        // Fail-Fast on UTF-8 Errors
        /*if(messageOpcode == OpText)
        {
            if(validate_partial(ApplicationData) != OK)
                close(DataInconsistent);
        }*/

        if (isFinalFragment)
			handleMessage();
	};
	break;
	} /* while (true) switch */
}

void QWsSocket::handleControlOpcode(const QByteArray &data)
{
	// According to http://tools.ietf.org/html/rfc6455#section-5.5
	// all control frames MUST have a payload length of 125 bytes or less
	if (payloadLength > 125)
	{
		close(ProtocolError);
		return;
	}

	// ... and MUST NOT be fragmented
	if (!isFinalFragment)
	{
		close(ProtocolError);
		return;
	}

	switch (frameOpcode)
	{
	case OpPing:
		writeFrame(QWsSocket::composeHeader(true, OpPong, data.size()));
		writeFrame(data);
		break;
	case OpPong:
		emit pong(pingTimer.elapsed());
		break;
	case OpClose:
		handleClose(data);
		break;
	case OpReserved6:
	case OpReserved7:
	case OpReserved8:
	case OpReserved9:
	case OpReserved10:
		close(ProtocolError);
		break;
	default:
		qDebug("Unexpected non-control opcode 0x%x within control opcode handling routine", frameOpcode);
		break;
	}
}

void QWsSocket::handleClose(const QByteArray &data)
{
	switch (payloadLength)
	{
	case 0:
		close(NormalClosure);
		return;
	case 1:
		close(ProtocolError);
		return;
	default:
		break;
	}

	const uchar * statusBuffer = reinterpret_cast<const uchar *>(data.constData());
	quint16 status = qFromBigEndian<quint16>(statusBuffer);
	switch (status)
	{
	case NormalClosure:
	case GoingAway:
	case ProtocolError:
	case UnsupportedDataType:
	case DataInconsistent:
	case PolicyViolated:
	case MessageTooBig:
	case RequiredExtensionUnsupported:
	// See https://groups.google.com/forum/?fromgroups#!topic/autobahnws/b5q9ux6DMcA
	case InternalServerError: // Is not sent by client
		break;
	default:
		if ((status <= StandardStatusReserveEnd)
			|| (status > VendorStatusReserveEnd))
		{
			close(ProtocolError);
			return;
		}
		break;
	}

	const char * reasonBuffer = data.constData() + sizeof(quint16);
	int reasonLength = payloadLength - sizeof(quint16);

    int unicodeOk = validate(QByteArray(reasonBuffer, reasonLength));
    close(unicodeOk == OK ? NormalClosure : DataInconsistent);
}

void QWsSocket::handleMessage()
{
	switch (messageOpcode)
	{
	case OpBinary:
        message.data = currentFrame;
        message.type = binary;
        emit frameReceived( message );
	    break;
    case OpText:
		// Handle UTF-8 errors as per http://tools.ietf.org/html/rfc6455#section-8.1,
		// i.e. close socket with an 1007 error code,
		// see http://tools.ietf.org/html/rfc6455#section-7.4.1
        if (validate(currentFrame) == OK)
        {
            message.data = currentFrame;
            message.type = text;
            emit frameReceived(message);
        }
        else
            close(DataInconsistent);
        break;
	case OpReserved1:
	case OpReserved2:
	case OpReserved3:
	case OpReserved4:
	case OpReserved5:
		close(ProtocolError);
		break;
	default:
		qDebug("Unexpected non-control opcode 0x%x", messageOpcode);
		break;
	}

	currentFrame.clear();
	messageOpcode = OpContinue;
}

qint64 QWsSocket::write ( const SocketMessage & message, int maxFrameBytes )
{
    if ( maxFrameBytes == 0 )
        maxFrameBytes = maxBytesPerFrame;

    QList<QByteArray> framesList;
    if(message.type == binary)
        framesList = QWsSocket::composeFrames( message.data, true, maxFrameBytes );
    else
        framesList = QWsSocket::composeFrames( message.data, false, maxFrameBytes );
    return writeFrames( framesList );
}

qint64 QWsSocket::writeFrame ( const QByteArray & byteArray )
{
    return tcpSocket->write( byteArray );
}

qint64 QWsSocket::writeFrames ( QList<QByteArray> framesList )
{
	qint64 nbBytesWritten = 0;
	for ( int i=0 ; i<framesList.size() ; i++ )
	{
		nbBytesWritten += writeFrame( framesList[i] );
	}
	return nbBytesWritten;
}

void QWsSocket::close(quint16 status, const QString &reason)
{
	// Compose and send close frame
	QByteArray reasonUtf = reason.toUtf8();
	quint64 messageSize = reasonUtf.size() + sizeof(quint16);

	uchar statusBuffer[sizeof(quint16)];
	qToBigEndian<quint16>(status, statusBuffer);

	tcpSocket->write(QWsSocket::composeHeader(true, OpClose, messageSize));
	tcpSocket->write(reinterpret_cast<const char *>(statusBuffer));
	if (reasonUtf.size() > 0)
		tcpSocket->write(reasonUtf);

	tcpSocket->close();
}

void QWsSocket::tcpSocketAboutToClose()
{
	emit aboutToClose();
}

void QWsSocket::tcpSocketDisconnected()
{
	emit disconnected();
}

QByteArray QWsSocket::generateMaskingKey()
{
	QByteArray key;
	for ( int i=0 ; i<4 ; i++ )
	{
		key.append( qrand() % 0x100 );
	}

	return key;
}

QByteArray QWsSocket::mask( QByteArray data, QByteArray maskingKey )
{
	for ( int i=0 ; i<data.size() ; i++ )
	{
		data[i] = ( data[i] ^ maskingKey[ i % 4 ] );
	}

	return data;
}

QList<QByteArray> QWsSocket::composeFrames( QByteArray byteArray, bool asBinary, int maxFrameBytes )
{
	if ( maxFrameBytes == 0 )
		maxFrameBytes = maxBytesPerFrame;

	QList<QByteArray> framesList;

	// As per http://tools.ietf.org/html/rfc6455#section-5.1
	// server MUST NOT mask the payload,
	// the earlier spec versions do not enforce that
	// but they should work ok w/o masking as well.

	int nbFrames = byteArray.size() / maxFrameBytes + 1;

	for ( int i=0 ; i<nbFrames ; i++ )
	{
		QByteArray BA;

		// fin, size
		bool fin = false;
		quint64 size = maxFrameBytes;
		EOpcode opcode = OpContinue;
		if ( i == nbFrames-1 ) // for multi-frames
		{
			fin = true;
            size = byteArray.size() - (i*size);
		}
		if ( i == 0 )
		{
			if ( asBinary )
				opcode = OpBinary;
			else
                opcode = OpText;
		}
		
		// Header
		QByteArray header = QWsSocket::composeHeader(fin, opcode, size);
		BA.append( header );
		
		// Application Data	
        BA.append(byteArray.mid(i*size, size));
		
		framesList << BA;
	}

	return framesList;
}

QByteArray QWsSocket::composeHeader( bool fin, EOpcode opcode, quint64 payloadLength, QByteArray maskingKey )
{
	QByteArray BA;
	quint8 byte;

	// FIN, RSV1-3, Opcode
	byte = 0x00;
	// FIN
	if ( fin )
		byte = (byte | 0x80);
	// Opcode
	byte = (byte | opcode);
	BA.append( byte );

	// Mask, PayloadLength
	byte = 0x00;
	QByteArray BAsize;
	// Mask
	if ( maskingKey.size() == 4 )
		byte = (byte | 0x80);
	// PayloadLength
	if ( payloadLength <= 125 )
	{
		byte = (byte | payloadLength);
	}
	// Extended payloadLength
	else
	{
		// 2 bytes
		if ( payloadLength <= 0xFFFF )
		{
			byte = ( byte | 126 );
			// TODO: Use QtEndian instead
			BAsize.append( ( payloadLength >> 1*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 0*8 ) & 0xFF );
		}
		// 8 bytes
		else if ( payloadLength <= 0x7FFFFFFF )
		{
			byte = ( byte | 127 );
			// TODO: Use QtEndian instead
			BAsize.append( ( payloadLength >> 7*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 6*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 5*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 4*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 3*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 2*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 1*8 ) & 0xFF );
			BAsize.append( ( payloadLength >> 0*8 ) & 0xFF );
		}
	}
	BA.append( byte );
	BA.append( BAsize );

	// Masking
	if ( maskingKey.size() == 4 )
		BA.append( maskingKey );

	return BA;
}

void QWsSocket::ping()
{
	pingTimer.restart();
	QByteArray pingFrame = QWsSocket::composeHeader( true, OpPing, 0 );
	writeFrame( pingFrame );
}

QString QWsSocket::composeOpeningHandShake( QString ressourceName, QString host, QString origin, QString extensions, QString key )
{
	QString hs;
	hs.append("GET /ws HTTP/1.1\r\n");
	hs.append("Host: pmx\r\n");
	hs.append("Upgrade: websocket\r\n");
	hs.append("Connection: Upgrade\r\n");
	hs.append("Sec-WebSocket-Version: 6\r\n");
	hs.append("Sec-WebSocket-Origin: http://pmx\r\n");
	hs.append("Sec-WebSocket-Extensions: deflate-stream\r\n");
	hs.append("Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");
	hs.append("\r\n");
	return hs;
}

int QWsSocket::validate(QByteArray a)
{
    qint64 err = 0;
    DecoderState state = newDecoderState();
    foreach(char byte, a) {
        err = process_byte(byte, &state);

        // Fail-Fast
        if (err != OK)
            return err;
    }

    // End processing
    return process_byte(0x0, &state, true);
}

int QWsSocket::validate_partial(QByteArray a)
{
    qint64 err = 0;
    DecoderState state = newDecoderState();
    foreach(char byte, a) {
        err = process_byte(byte, &state);

        // Fail-Fast
        if (err != OK)
            return err;
    }

    return OK;
}

QWsSocket::DecoderState QWsSocket::newDecoderState()
{
    DecoderState state;
    state.bytes_so_far = 0;
    state.expecting_continuation = 0;
    state.unichars_so_far = 0;
    state.working_len = 0;
    return state;
}

int QWsSocket::process_byte(quint8 incoming, DecoderState *state, bool do_nothing)
{
    int i, err = 0;
    quint32 unichar;
    quint8 *working = state->working;
    if (state->expecting_continuation > 0) {
        if ((incoming & 0xC0) != 0x80) { // not a continuation char
            err = MISSING_CONTINUATION;
            state->bytes_so_far += state->working_len;
            state->working_len = 0;
            state->expecting_continuation = 0;
            process_byte(incoming, state); // reprocess
            return err;
        }
        // else, got a continuation char
        state->working[state->working_len] = incoming;
        state->working_len++;
        state->expecting_continuation--;
        if (state->expecting_continuation == 0) { // finished the unichar
            if (((working[0] & 0xFE) == 0xC0) ||
                ((working[0] == 0xE0) && ((working[1] & 0x20) == 0x00)) ||
                ((working[0] == 0xF0) && ((working[1] & 0x30) == 0x00)) ||
                ((working[0] == 0xF8) && ((working[1] & 0x38) == 0x00)) ||
                ((working[0] == 0xFC) && ((working[1] & 0x3C) == 0x00))) {
                err = OVERLONG_FORM;
                state->bytes_so_far += state->working_len;
                state->working_len = 0;
                state->expecting_continuation = 0;
                return err;
            }
            unichar = 0;
            if ((working[0] & 0xE0) == 0xC0) {
                unichar = working[0] & 0x1F;
            } else if ((working[0] & 0xF0) == 0xE0) {
                unichar = working[0] & 0x0F;
            } else if ((working[0] & 0xF8) == 0xF0) {
                unichar = working[0] & 0x07;
            } else {
                unichar = 1; // will be OUT_OF_RANGE
            }
            for(i=1; i < state->working_len; i++) {
                unichar <<= 6;
                unichar += state->working[i] & 0x3F;
            }
            err = OK;
            if (unichar > 0x10FFFF) {
                err = OUT_OF_RANGE;
            } else if ((unichar & 0xF800) == 0xD800) {
                err = BAD_SCALAR_VALUE;
            }
            if (err != 0) {
                state->bytes_so_far += state->working_len;
                state->working_len = 0;
                state->expecting_continuation = 0;
            } else {
                if(!do_nothing)
                    state->unichars_so_far++;
                state->bytes_so_far += state->working_len;
                state->working_len = 0;
                state->expecting_continuation = 0;
            }
        }
        return err;
    } // expecting_continuation

    if ((incoming & 0x80) == 0) { // ASCII
        state->working[0] = incoming;
        if(!do_nothing)
            state->unichars_so_far++;
        state->bytes_so_far++;
    } else if (((incoming & 0xC0) == 0x80) ||
               ((incoming & 0xFE) == 0xFE)) { // continuation but unexpected, or 0xFE-0xFF
        if ((incoming & 0xFE) == 0xFE) {
          err = INVALID;
        } else {
          err = UNEXPECTED_CONTINUATION;
        }
        state->working[0] = incoming;
        state->bytes_so_far++;
        state->working_len = 0;
        state->expecting_continuation = 0;
    } else { // start of a multi-byte sequence
        state->working[0] = incoming;
        state->working_len = 1;
        if ((incoming & 0xE0) == 0xC0) { // start of 2-char sequence
            state->expecting_continuation = 1;
        } else if ((incoming & 0xF0) == 0xE0) { // start of 3-char sequence
            state->expecting_continuation = 2;
        } else if ((incoming & 0xF8) == 0xF0) { // start of 4-char sequence
            state->expecting_continuation = 3;
        } else if ((incoming & 0xFC) == 0xF8) { // start of 5-char sequence -- will be OUT_OF_RANGE if complete
            state->expecting_continuation = 4;
        } else if ((incoming & 0xFE) == 0xFC) { // start of 6-char sequence -- will be OUT_OF_RANGE if complete
            state->expecting_continuation = 5;
        }
    }
    return err;
}

package ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class SecureConnection
{
    private final int _timeout;
    private boolean _handshakeCompleted;
    private Transport _transport;
    private Endpoint _endpoint;
    private SSLEngine _sslEngine;
    private Listener _listener;
    private DataDecryptionHandler _dataDecryptionHandler;
    private DataEncryptionHandler _dataEncryptionHandler;
    private HandshakeHandler _handshakeHandler;

    public SecureConnection(SSLContext _context, RegistrationParams registrationParams, Listener listener)
    {
        _listener = listener;
        _sslEngine = _context.createSSLEngine();
        _sslEngine.setUseClientMode(registrationParams.shouldUseClientMode());
        _transport = registrationParams.getTransport();
        _endpoint = registrationParams.getEndpoint();
        _timeout = registrationParams.getTimeout();
        _handshakeHandler = new HandshakeHandler(_sslEngine, new HandshakeHandler.HandshakeListener()
        {
            @Override
            public void handshakeCompleted()
            {
                _handshakeCompleted = true;
                _listener.connectionSecured(_endpoint);
            }

            @Override
            public void handshakeAborted()
            {
                 //TODO: any cleanup
                _listener.connectionClosed(_endpoint);
            }

            @Override
            public void handshakeDataAvailable(ByteBuffer buffer)
            {
                _transport.send(buffer);
            }
        });
        //TODO: move listener creation to factory
        _dataDecryptionHandler = new DataDecryptionHandler(_sslEngine, new DataDecryptionHandler.DecryptedDataListener()
        {
            @Override
            public void decryptedDataAvailable(ByteBuffer buffer)
            {
                _listener.plainTextData(_endpoint, buffer);
            }

            @Override
            public void renegotiationRequired()
            {
            }

            @Override
            public void error()
            {
                 //TODO: any cleanup
                _listener.connectionClosed(_endpoint);
            }
        });
        //TODO: move listener creation to factory
        try
        {
            _dataEncryptionHandler = new DataEncryptionHandler(_sslEngine, new DataEncryptionHandler.EncryptedDataListener()
            {
                @Override
                public void encryptedDataAvailable(ByteBuffer byteBuffer)
                {
                    _transport.send(byteBuffer);
                }

                @Override
                public void error()
                {
                    //TODO: any cleanup
                    _listener.connectionClosed(_endpoint);
                }
            });
        }
        catch (IOException e)
        {
            _listener.connectionClosed(_endpoint);
        }
    }

    public void encryptedDataReceived(ByteBuffer encryptedData)
    {
        if(_handshakeCompleted)
        {
            _dataDecryptionHandler.addToBuffer(encryptedData);
        }
        else
        {
            _handshakeHandler.encryptedDataReceived(encryptedData);
        }
    }

    public void encryptAndSend(ByteBuffer plainText)
    {
        _dataEncryptionHandler.addToBuffer(plainText);
    }

    public void cleanup()
    {
        try
        {
            _sslEngine.closeOutbound();
            _sslEngine.closeInbound();
        }
        catch (SSLException ignored)
        {
        }
        _listener.connectionClosed(_endpoint);
    }

    public void shakeHands()
    {
       _handshakeHandler.shakeHands();
    }
}

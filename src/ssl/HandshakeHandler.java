package ssl;

import ssl.Utils.Utils;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class HandshakeHandler
{
    private final SSLEngine _sslEngine;
    private final HandshakeListener _listener;
    private final ByteBuffer _wrappedData = ByteBuffer.wrap(new byte[0]);

    public HandshakeHandler(SSLEngine sslEngine, HandshakeListener listener)
    {
        _sslEngine = sslEngine;
        _listener = listener;
    }

    public void shakeHands()
    {
        while (true)
        {
            SSLEngineResult.HandshakeStatus handshakeStatus = _sslEngine.getHandshakeStatus();
            switch (handshakeStatus)
            {
                case FINISHED:
                    finishHandshake();
                    return;
                case NOT_HANDSHAKING:
                    return;
                case NEED_TASK:
                    processLongRunningTask();
                    break;
                case NEED_WRAP:
                    SSLEngineResult result;
                    try
                    {
                        ByteBuffer handshakeData = Utils.allocateByteBuffer(_sslEngine, Utils.Operation.SENDING);
                        result = Utils.encrypt(_sslEngine, new byte[0], handshakeData);
                        _listener.handshakeDataAvailable(handshakeData);
                        if (isHandshakeFinished(result))
                        {
                            finishHandshake();
                            return;
                        }
                    }
                    catch (IOException e)
                    {
                        _listener.handshakeAborted();
                    }
                    break;
                case NEED_UNWRAP:
                    try
                    {
                        ByteBuffer decryptedData = Utils.allocateByteBuffer(_sslEngine, Utils.Operation.RECEIVING);
                        SSLEngineResult unwrapResult = Utils.decrypt(false, _sslEngine, ByteBuffer.wrap(new byte[0]), decryptedData);
                        if (unwrapResult.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP))
                        {
                            return;
                        }
                        else if (isHandshakeFinished(unwrapResult))
                        {
                            finishHandshake();
                            return;
                        }
                        else
                        {
                            break;
                        }
                    }
                    catch (IOException exception)
                    {
                        _listener.handshakeAborted();
                    }
                    return;
            }
        }
    }

    private boolean isHandshakeFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }

    private void processLongRunningTask()
    {
        Utils.processLongRunningTask(_sslEngine);
    }

    private void finishHandshake()
    {
        _listener.handshakeCompleted();
    }

    public void encryptedDataReceived(ByteBuffer encryptedData)
    {
        _wrappedData.put(encryptedData);
        shakeHands();
    }

    public interface HandshakeListener
    {
        public void handshakeCompleted();

        public void handshakeAborted();

        public void handshakeDataAvailable(ByteBuffer buffer);
    }
}

package ssl;

import ssl.Utils.Utils;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class DataDecryptionHandler
{
    private final SSLEngine _sslEngine;
    private final DecryptedDataListener _listener;
    private final ByteBuffer encryptedDataBuffer = ByteBuffer.wrap(new byte[0]);

    public DataDecryptionHandler(SSLEngine sslEngine, DecryptedDataListener listener)
    {
        _sslEngine = sslEngine;
        _listener = listener;
    }

    public void addToBuffer(ByteBuffer encryptedData)
    {
        encryptedDataBuffer.put(encryptedData);
        try
        {
            ByteBuffer unwrappedData;
            unwrappedData = Utils.allocateByteBuffer(_sslEngine, Utils.Operation.RECEIVING);
            SSLEngineResult result = Utils.decrypt(true, _sslEngine, unwrappedData, encryptedData);
            //TODO: check result for SSL renegotiation
            _listener.decryptedDataAvailable(unwrappedData);
        }
        catch (IOException e)
        {
            _listener.error();
        }
    }

    public interface DecryptedDataListener
    {
        public void decryptedDataAvailable(ByteBuffer buffer);

        public void renegotiationRequired();

        public void error();
    }
}

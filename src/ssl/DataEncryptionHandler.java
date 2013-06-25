package ssl;

import ssl.Utils.Utils;

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.nio.ByteBuffer;

public class DataEncryptionHandler
{
    private final SSLEngine _sslEngine;
    private final EncryptedDataListener _listener;
    private final ByteBuffer _plainTextBuffer;

    public DataEncryptionHandler(SSLEngine sslEngine, EncryptedDataListener listener) throws IOException
    {
        _sslEngine = sslEngine;
        _listener = listener;
        _plainTextBuffer = Utils.allocateByteBuffer(_sslEngine, Utils.Operation.SENDING);
    }

    public void addToBuffer(ByteBuffer plainText)
    {
        _plainTextBuffer.put(plainText);
        try
        {
            ByteBuffer encryptedData = Utils.allocateByteBuffer(_sslEngine, Utils.Operation.SENDING);
            _sslEngine.wrap(plainText,encryptedData);
            _listener.encryptedDataAvailable(encryptedData);
        }
        catch (IOException e)
        {
            _listener.error();
        }
    }

    public interface EncryptedDataListener
    {
        public void encryptedDataAvailable(ByteBuffer byteBuffer);

        public void error();
    }
}

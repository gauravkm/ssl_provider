package ssl.Utils;


import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;

public class Utils
{

    static SSLContext getSSLContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException
    {
        String password = "android@39";
        char[] passphrase = password.toCharArray();
        // First initialize the key and trust material.
        String keystore = "android-ssc.jks";
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream(keystore);
        ks.load(stream, passphrase);
        stream.close();
        SSLContext sslContext = SSLContext.getInstance("TLS");

        // TrustManager's decide whether to allow connections.
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        // KeyManager's decide which key material to use.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, passphrase);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    private static byte[] getSSLMessageBytesFromBuffer(ByteBuffer encryptedData, SSLEngineResult result)
    {
        byte[] sslMessage = new byte[result.bytesProduced()];
        encryptedData.get(sslMessage, 0, result.bytesProduced());
        return sslMessage;
    }

    public static void processLongRunningTask(SSLEngine sslEngine)
    {
        Runnable task;
        while ((task = sslEngine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }


    public static SSLEngineResult encrypt(SSLEngine sslEngine, byte[] data, ByteBuffer outgoingData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        return sslEngine.wrap(applicationData, outgoingData);
    }

    public static SSLEngineResult decrypt(boolean handshakeCompleted, SSLEngine sslEngine, ByteBuffer unwrappedData, ByteBuffer totalIncomingData) throws IOException
    {
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        int totalBytesToBeConsumed = totalIncomingData.array().length;
        do
        {
            result = sslEngine.unwrap(totalIncomingData, unwrappedData);
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
        }
        while (needsUnwrap(handshakeCompleted, result, totalBytesConsumed, totalBytesToBeConsumed));
        return result;
    }

    private static boolean needsUnwrap(boolean handshakeCompleted, SSLEngineResult result, int totalBytesConsumed, int totalBytesToBeConsumed)
    {
        if (!handshakeCompleted)
        {
            return result.getStatus() == SSLEngineResult.Status.OK && result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) && result.bytesProduced() == 0;
        }
        else
        {
            return result.getStatus() == SSLEngineResult.Status.OK && (result.bytesProduced() != 0 || totalBytesConsumed < totalBytesToBeConsumed);
        }
    }

    public static ByteBuffer allocateByteBuffer(SSLEngine sslEngine, Operation operation) throws IOException
    {
        SSLSession session = sslEngine.getSession();
        int bufferSize;
        if (operation == Operation.SENDING)
        {
            bufferSize = session.getPacketBufferSize();
        }
        else
        {
            bufferSize = session.getApplicationBufferSize();
        }
        return ByteBuffer.allocate(bufferSize);
    }

    private static byte[] copyToByteArray(ByteBuffer outgoingData, int size)
    {
        outgoingData.flip();
        byte[] bytes = new byte[size];
        outgoingData.get(bytes, 0, size);
        return bytes;
    }

    public enum Operation
    {
        SENDING, RECEIVING
    }
}

package ssl;

import javax.net.ssl.SSLContext;
import java.nio.ByteBuffer;

public abstract class ASSLProvider
{
    protected final SSLContext _context;
    protected final boolean _useClientMode;

    public ASSLProvider(SSLContext context, boolean useClientMode)
    {
        _context = context;
        _useClientMode = useClientMode;
    }

    public abstract void register(RegistrationParams registrationParams, Listener listener);

    public abstract void encryptedDataReceived(Endpoint endpoint, ByteBuffer encryptedData);

    public abstract void encryptAndSend(Endpoint endpoint, ByteBuffer plainText);

    public abstract void deregister(Endpoint endpoint);
}

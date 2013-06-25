package ssl;

import javax.net.ssl.SSLContext;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class SSLProvider extends ASSLProvider
{
    private Map<Endpoint, SecureConnection> _secureConnectionCache = new HashMap<>();

    public SSLProvider(SSLContext context, boolean useClientMode)
    {
        super(context, useClientMode);
    }

    @Override
    public void register(RegistrationParams registrationParams, Listener listener)
    {
        registrationParams.setUseClientMode(_useClientMode);
        SecureConnection connection = new SecureConnection(_context, registrationParams, listener);
        _secureConnectionCache.put(registrationParams.getEndpoint(), connection);
        //TODO: start handshake?
    }

    @Override
    public void encryptedDataReceived(Endpoint endpoint, ByteBuffer encryptedData)
    {
        SecureConnection connection = _secureConnectionCache.get(endpoint);
        if (connection != null)
        {
            connection.encryptedDataReceived(encryptedData);
        }
        else
        {
            //TODO: throw connection not registered exception
        }
    }

    @Override
    public void encryptAndSend(Endpoint endpoint, ByteBuffer plainText)
    {
        SecureConnection connection = _secureConnectionCache.get(endpoint);
        if (connection != null)
        {
            connection.encryptAndSend(plainText);
        }
        else
        {
            //TODO: throw connection not registered exception
        }
    }

    @Override
    public void deregister(Endpoint endpoint)
    {
        SecureConnection connection = _secureConnectionCache.get(endpoint);
        if (connection != null)
        {
            connection.cleanup();
            _secureConnectionCache.remove(endpoint);
        }
        else
        {
            //TODO: throw connection not registered exception
        }

    }
}

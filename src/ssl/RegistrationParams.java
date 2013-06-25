package ssl;

public class RegistrationParams
{
    private final Endpoint _endpoint;
    private final Transport _transport;
    private int _timeout;
    private boolean _useClientMode;

    public RegistrationParams(Endpoint endpoint, Transport transport)
    {
        _endpoint = endpoint;
        _transport = transport;
    }

    public Endpoint getEndpoint()
    {
        return _endpoint;
    }

    public Transport getTransport()
    {
        return _transport;
    }

    public int getTimeout()
    {
        return _timeout;
    }

    public void setUseClientMode(boolean useClientMode)
    {
        _useClientMode = useClientMode;
    }

    public boolean shouldUseClientMode()
    {
        return _useClientMode;
    }
}

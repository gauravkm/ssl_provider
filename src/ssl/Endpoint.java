package ssl;

import java.net.InetAddress;

public class Endpoint
{
    private final InetAddress _address;
    private final int _port;

    public Endpoint(InetAddress inetAddress, int port)
    {
        _address = inetAddress;
        _port = port;
    }
}

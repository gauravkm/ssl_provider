package ssl;

import java.nio.ByteBuffer;

public interface Listener
{
    public void connectionSecured(Endpoint endpoint);

    public void plainTextData(Endpoint endpoint, ByteBuffer plainText);

    public void connectionClosed(Endpoint endpoint);
}

package eu.unicore.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

/**
 * helpers for dealing with Channel I/O
 * 
 * This differs from the corresponding methods in {@link Channels} by
 *   1. allowing to use a buffer with a given size
 *   2. it will NOT check for blocking mode
 * as required when using {@link SSLSocketChannel}
 * 
 * @author schuller
 */
public class ChannelUtils {

	private ChannelUtils() {}

	/**
	 * Note: do NOT mix this with non-blocking I/O, it will probably end badly.
	 * 
	 * @param ch
	 * @param bufferSize
	 */
    public static OutputStream newOutputStream(final WritableByteChannel ch, final int bufferSize) {
        Objects.requireNonNull(ch, "ch");

        return new OutputStream() {

            private final ByteBuffer bb = ByteBuffer.allocate(bufferSize);

            @Override
            public synchronized void write(int b) throws IOException {
                this.write(new byte[]{(byte)b});
            }

            @Override
            public synchronized void write(byte[] bs, int off, int len)
                    throws IOException
            {
                if ((off < 0) || (off > bs.length) || (len < 0) ||
                    ((off + len) > bs.length) || ((off + len) < 0)) {
                    throw new IndexOutOfBoundsException();
                } else if (len == 0) {
                    return;
                }
                bb.clear();
                bb.put(bs,0,len);
                bb.flip();
                writeFully(ch, bb);
            }

            @Override
            public void close() throws IOException {
                ch.close();
            }

        };
    }
    
    /**
	 * Note: do NOT mix this with non-blocking I/O, it will probably end badly.
	 * 
	 * @param ch
	 * @param bufferSize
	 */
    public static InputStream  newInputStream(final ReadableByteChannel ch, final int bufferSize) {
    	return new InputStream() {
			
			private final ByteBuffer bb = ByteBuffer.allocate(bufferSize);
			
			@Override
			public int read() throws IOException {
				byte[] b = new byte[1];
				int read = read(b);
				if (read ==-1){
					return -1;
				}
				else {
					return (b[0] & 0xff);
				}
			}

			@Override
			public int read(byte[] b) throws IOException {
				return read(b, 0, b.length);
			}

			@Override
			public synchronized int read(byte[] b, int off, int len) throws IOException {
				if(len==0)return 0;
				bb.clear();
				int n = 0;
				while(n==0) {
					n = ch.read(bb);
					if(n<0)return -1;
					if(n==0)try {
						Thread.sleep(10);
					}catch(InterruptedException ie) {}
				}
				bb.flip();
				bb.get(b, off, n);
				return n;
			}

			@Override
			public void close() throws IOException {
				ch.close();
			}
			
		};
    }
    
    /**
     * Write all remaining bytes in the buffer to the given channel.
     *
     * @throws  IOException if the channel is closed.
     */
    public static void writeFully(WritableByteChannel ch, ByteBuffer bb)
    		throws IOException
    {
    	int written = 0;
    	int to_write = bb.remaining();
    	while (written<to_write) {
    		int n = ch.write(bb);
    		if (n < 0)
    			throw new IOException("no bytes written");
    		written+=n;
    		if(n==0)try{
    			Thread.sleep(10);
    		}catch(InterruptedException ie) {}
    	}
    }
	
}

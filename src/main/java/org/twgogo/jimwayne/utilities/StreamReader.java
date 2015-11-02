package org.twgogo.jimwayne.utilities;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;

import org.bouncycastle.util.encoders.Hex;

/**
 * Read bytes from a File or an InputStream. 
 * @author Wayne
 */
public class StreamReader {
	/**
	 * Get bytes from a File.
	 * @param f
	 * @return A byte array representing the specified File. <code>null</code> is returned if the specified File is not exists.
	 */
	public static byte[] get (File f) {
		if(f.exists()) {
			try (FileInputStream fis = new FileInputStream(f);) {
				return get(fis);
			} catch (IOException e) {
				return null;
			}
		}
		return null;
	}
	
	/**
	 * Get bytes from an InputStream.
	 * @param is
	 * @return An byte array containing all the bytes read from the InputStream. 
	 * 			<code>null</code> is returned if error occurred when reading inputs.
	 * @throws SocketTimeoutException
	 */
	public static byte[] get (InputStream is) throws SocketTimeoutException {
		try {
			return get(is, "");
		} catch (IllegalAccessException e) {
			return null;
		}
	}
	
	/**
	 * Get bytes from an InputStream.
	 * @param is
	 * @param md5Hash
	 * @return An byte array containing all the bytes read from the InputStream. 
	 * 			<code>null</code> is returned if error occurred when reading inputs.
	 * @throws SocketTimeoutException
	 * @throws IllegalAccessException MD5 error.
	 */
	public static byte[] get (InputStream is, String md5Hash) throws SocketTimeoutException, IllegalAccessException {
		// Read the response from server
		byte[] returnedBytes = null;
		byte[] buffer = new byte[128];
		LinkedList<byte[]> downloadedList = new LinkedList<byte[]>();
		
		int len;
		int downloaded = 0; // The total length of downloaded bytes.
		try {
			while (true) {
				// Read from stream.
				len = is.read(buffer);

				if (len == -1) {
					// Reading ends.
					break;
				} else {
					byte[] currentBytes = new byte[len];
					System.arraycopy(buffer, 0, currentBytes, 0, len);
					downloadedList.add(currentBytes);
				}
				downloaded += len;
			}
			
			// Construct the returned byte array by collecting all the bytes from the list.
			returnedBytes = new byte[downloaded];
			int copiedIndex = 0;
			Iterator<byte[]> list = downloadedList.iterator();
			while(list.hasNext()) {
				byte[] currentBytes = list.next();
				System.arraycopy(currentBytes, 0, returnedBytes, copiedIndex, currentBytes.length);
				copiedIndex += currentBytes.length;
			}
			
			// If MD5 is given, check the stream result.
			if(md5Hash != null && md5Hash.length() > 0) {
				//System.out.println("[StreamReader] Check MD5");
				ByteArrayInputStream bais = null;
				DigestInputStream dis = null;
				MessageDigest digest = null;
				try {
					digest = MessageDigest.getInstance("MD5");
					bais = new ByteArrayInputStream(returnedBytes);
					dis = new DigestInputStream(bais, digest);
					
					while (dis.read(buffer) > 0) {}
					
					String receiveMD5 = Hex.toHexString(digest.digest());
					if(receiveMD5.compareToIgnoreCase(md5Hash) != 0)
						throw new IllegalAccessException("The MD5 of the request body is not correct.");
					//else
					//	System.out.println("[StreamReader] MD5 OK.");
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} finally {
					if(dis != null) dis.close();
					if(bais != null) bais.close();
				}
			}
			
			return returnedBytes;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} finally {
			try {
				if (is != null) is.close();
			} catch (Exception e) {}
		}
	}
	
	/**
	 * Get String from an InputStream using specified {@code Charset}.
	 * @param is
	 * @param charset
	 * @return
	 */
	public static String get (InputStream is, Charset charset) throws SocketTimeoutException {
		byte[] bytes = get(is);
		return new String(bytes, charset);
	}
	
	/**
	 * Get String from an InputStream using specified {@code Charset}.
	 * @param is
	 * @param md5Hash
	 * @param charset
	 * @return
	 * @throws SocketTimeoutException
	 */
	public static String get (InputStream is, String md5Hash, Charset charset) throws SocketTimeoutException, IllegalAccessException {
		byte[] bytes = get(is, md5Hash);
		return new String(bytes, charset);
	}
}

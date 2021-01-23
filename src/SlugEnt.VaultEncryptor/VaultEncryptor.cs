using System;
using System.IO;
using System.Security.Cryptography;

namespace SlugEnt.VaultEncryptor
{
	/// <summary>
	/// Enables the Encrpytion of secret pieces of data
	/// </summary>
	public class VaultEncryptor {
		// This must NOT Be changed - EVER. It may break existing encrypted objects.  Serious, as in significant testing should
		// be performed if this is changed.
		private const int BIT_SIZE = 128;
		private const int BYTE_SIZE = 16;
		private const int IV_SIZE = 16;


		/// <summary>
		/// <para>Encryption Mode used is AES 256 bit with CBC algorithm</para>
		/// </summary>
		public VaultEncryptor () { }


		/// <summary>
		/// Returns the Bit Size of encryption Algorithm
		/// </summary>
		public int BitSize {
			get { return BIT_SIZE; }
		}



		/// <summary>
		/// Returns the number of Bytes required for Key and IV
		/// </summary>
		public int ByteSize {
			get { return (BYTE_SIZE); }
		}


		/// <summary>
		/// Returns the IV required size in Bytes.
		/// </summary>
		public int IVSize {
			get { return IV_SIZE; }
		}


		public byte [] Encrypt (string keyName, byte [] secret, string dataToEncrypt) {
			return Encrypt(keyName, secret, null, dataToEncrypt);
		}



		/// <summary>
		/// Encrypts the given data
		/// </summary>
		/// <param name="secret">The secret for the encrypted data.</param>
		/// <param name="iv"></param>
		/// <param name="data"></param>
		/// <returns></returns>
		public byte [] Encrypt (string keyName, byte [] secret, byte [] iv, string dataToEncrypt) {
		if ( string.IsNullOrEmpty(keyName) ) throw new ArgumentException("The parameter [keyName] cannot be empty or null");
		if ( keyName.Length != 16 ) throw new ArgumentException("The parameter [keyName] must be exactly 16 characters in length");
		if ( secret.Length != BYTE_SIZE ) throw new ArgumentException("The parameter [secret] is not of the exact size required - " + BYTE_SIZE);


		using MemoryStream myStream = new MemoryStream();

		//Create a new instance of the default Aes implementation class  
		// and configure encryption key.  
		using Aes aes = Aes.Create();
		aes.Key = secret;

		//Stores IV at the beginning of the file.
		//This information will be used for decryption.
		if ( iv != null ) {
			if ( iv.Length != IV_SIZE ) throw new ArgumentException("The parameter [iv] is not of the exact size required - " + IV_SIZE);
		}
		else
			iv = aes.IV;

		myStream.Write(iv, 0, iv.Length);

		//Create a CryptoStream, pass it the FileStream, and encrypt it with the Aes class.  
		using CryptoStream cryptStream = new CryptoStream(myStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

		//Create a StreamWriter for easy writing to the stream
		using StreamWriter sWriter = new StreamWriter(cryptStream);

		//Write to the stream.  
		//sWriter.Write(data);
		sWriter.Write(dataToEncrypt); 
		//sWriter.Write("Trump is gone.  Trump is gone.  Trump never more.");

		sWriter.Flush();
		cryptStream.FlushFinalBlock();


		byte [] encrypted;
		encrypted = myStream.ToArray();
		return encrypted;

		//return myStream.ToArray();
	}


		public string Decrypt (string keyName, byte [] secret, byte [] encryptedData) {
			byte [] key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

			try {
				using MemoryStream myStream = new MemoryStream(encryptedData);

				//Create a new instance of the default Aes implementation class
				using Aes aes = Aes.Create();
				aes.Key = secret;

				//Reads IV value from beginning of the file.
				byte [] iv = new byte[IVSize];
				myStream.Read(iv, 0, iv.Length);
				aes.IV = iv;

				//Create a CryptoStream, pass it the file stream, and decrypt it with the Aes class using the key and IV.
				using CryptoStream cryptStream = new CryptoStream(myStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

				//Read the stream.
				using StreamReader sReader = new StreamReader(cryptStream);

				string de = sReader.ReadToEnd();
				return de;
			}
			catch ( System.Security.Cryptography.CryptographicException e ) {
				System.Security.Cryptography.CryptographicException newCryptographicException =
					new CryptographicException(
						"Unable to decrypt the encrypted stream.  It may be the secret is incorrect, the IV is incorrect, the padding encoding is incorrect or the encrypted stream is wrong or corrupted.",
						e);
				throw newCryptographicException;
			}
		}
	}
}

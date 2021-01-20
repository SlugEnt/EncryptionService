using System;
using System.IO;
using System.Security.Cryptography;

namespace SlugEnt.VaultEncryptor
{
	/// <summary>
	/// Enables the Encrpytion of secret pieces of data
	/// </summary>
	public class VaultEncryptor
	{
		// This must NOT Be changed - EVER. It may break existing encrypted objects.  Serious, as in significant testing should
		// be performed if this is changed.
		private const int BIT_SIZE = 256;
		private const int BYTE_SIZE = 32;

		/// <summary>
		/// <para>Encryption Mode used is AES 256 bit with CBC algorithm</para>
		/// </summary>
		public VaultEncryptor () {}


		/// <summary>
		/// Returns the Bit Size of encryption Algorithm
		/// </summary>
		public int BitSize {
			get { return BIT_SIZE; }
		}



		/// <summary>
		/// Returns the number of Bytes required for Key and IV
		/// </summary>
		public int ByteSize { get { return (BYTE_SIZE); }}



		/// <summary>
		/// Encrypts the given data
		/// </summary>
		/// <param name="secret">The secret for the encrypted data.</param>
		/// <param name="iv"></param>
		/// <param name="data"></param>
		/// <returns></returns>
		public byte[] Encrypt (string keyName, byte[] secret, byte[] iv, byte[] data) {
			if (string.IsNullOrEmpty(keyName)) throw new ArgumentException("The parameter [keyName] cannot be empty or null");
			if (keyName.Length != 16) throw new ArgumentException("The parameter [keyName] must be exactly 16 characters in length");
			if (secret.Length != BYTE_SIZE) throw new ArgumentException("The parameter [secret] is not of the exact size required - " + BYTE_SIZE);
			if (iv.Length != BYTE_SIZE) throw new ArgumentException("The parameter [iv] is not of the exact size required - " + BYTE_SIZE);


			using MemoryStream myStream = new MemoryStream();
			//Create a file stream

			//using FileStream myStream = new FileStream("TestData.txt", FileMode.OpenOrCreate);

			//Create a new instance of the default Aes implementation class  
			// and configure encryption secret.  
			using Aes aes = Aes.Create();
			aes.Key = secret;

			//Stores IV at the beginning of the file.
			//This information will be used for decryption.
			//byte[] iv = aes.IV;
			myStream.Write(iv, 0, iv.Length);

			//Create a CryptoStream, pass it the FileStream, and encrypt
			//it with the Aes class.  
			using CryptoStream cryptStream = new CryptoStream(
				myStream,
				aes.CreateEncryptor(),
				CryptoStreamMode.Write);

			//Create a StreamWriter for easy writing to the
			//file stream.  
			using StreamWriter sWriter = new StreamWriter(cryptStream);

			//Write to the stream.  
			sWriter.WriteLine("Hello World!");

			//Inform the user that the message was written  
			//to the stream.  
			Console.WriteLine("The file was encrypted.");
			return myStream.ToArray();
        }
	}
}

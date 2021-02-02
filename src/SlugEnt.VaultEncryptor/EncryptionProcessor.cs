using SlugEnt.Encryption.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SlugEnt.EncryptionService;


[assembly: InternalsVisibleTo("Test_EncryptionService")]


namespace SlugEnt.VaultEncryptor
{
	/// <summary>
	/// Enables the Encrpytion of secret pieces of data
	/// <para>4 Bytes KeyName</para>
	/// <para>2 Bytes Version # up 65535 (unsigned)</para>
	/// <para>8 Bytes Update Time</para>
	/// <para></para>
	/// </summary>
	public class EncryptionProcessor {
		private Aes aesEncryptor;
		private Dictionary<string, KeyRingMember> _keyRing;

		/// <summary>
		/// <para>Encryption Mode used is AES 256 bit with CBC algorithm</para>
		/// </summary>
		public EncryptionProcessor () {
			_keyRing = new Dictionary<string, KeyRingMember>();
			aesEncryptor = Aes.Create();
		}

		
		
		/*
				public byte [] EncryptWithStoredIV (string keyName, byte [] secret, string dataToEncrypt) {
					return EncryptWithStoredIV(keyName, secret, null, dataToEncrypt);
				}
		*/


		/// <summary>
		/// Adds the given EncryptionKeyVersioned object to the KeyRing.
		/// </summary>
		/// <param name="encryptionKeyVersioned"></param>
		internal void LoadEncyptionKey (EncryptionKeyVersioned encryptionKeyVersioned) {
			// 1st see if KeyName exists.  If not add it which also adds the EncryptionKeyVersioned object
			KeyRingMember member;
			if ( !_keyRing.TryGetValue(encryptionKeyVersioned.KeyNameShort, out member) ) {
				member = new KeyRingMember(encryptionKeyVersioned);
				_keyRing.TryAdd(member.KeyName, member);
			}
			else {
				// Add the EncryptionKeyVersioned.
				member.InsertVersion(encryptionKeyVersioned);
			}
		}



		/// <summary>
		/// Retrieves the secret for the version requested.
		/// </summary>
		/// <param name="keyName"></param>
		/// <param name="version"></param>
		/// <returns></returns>
		internal EncryptionKeyVersioned GetEncryptionKeyVersioned (string keyName, ushort version = 0) {
			// Do we have a KeyRing Entry for Keyname?
			KeyRingMember keyRingMember;
			bool exists = _keyRing.TryGetValue(keyName, out keyRingMember);
			if (!exists) throw new ArgumentException("No KeyRing could be found with a KeyName of [" + keyName + "]");

			if ( version == 0 ) return keyRingMember.CurrentKey;

			// Otherwise get the specific version requested.
			EncryptionKeyVersioned encryptionKeyVersioned =  keyRingMember.GetVersion(version);
			return encryptionKeyVersioned;
		}


		
		public byte [] Encrypt (string keyName, string dataToEncrypt) {
			// Get the Current EncryptionKeyVersioned object.  We always encrypt with the most current key.
			EncryptionKeyVersioned encryptionKeyVersioned = GetEncryptionKeyVersioned(keyName);
			
			// Create Encryption Header Prefix object
			EncryptorInfo encryptorInfo = new EncryptorInfo(keyName,encryptionKeyVersioned.Version, DateTime.Now);

			// Build Encrypted Data Stream
			// EncryptorInfo followed by Encrypted Data
			byte[] headerBytes = encryptorInfo.GetBytes();
			byte[] encryptedData = EncryptInternal(encryptionKeyVersioned.Secret, dataToEncrypt, encryptorInfo.GetIV());

			byte[] fullRecordBytes = new byte[headerBytes.Length + encryptedData.Length];
			Buffer.BlockCopy(headerBytes, 0, fullRecordBytes, 0, headerBytes.Length);
			Buffer.BlockCopy(encryptedData, 0, fullRecordBytes, headerBytes.Length, encryptedData.Length);

			return fullRecordBytes;
		}


		// Temporary
		public byte [] Encrypt (EncryptorInfo encryptorInfo, byte[] secret, string dataToEncrypt) {
			// Incomplete..
			byte [] headerBytes = encryptorInfo.GetBytes();

			byte[] encryptedData = EncryptInternal(secret, dataToEncrypt, encryptorInfo.GetIV());

			byte[] fullRecordBytes = new byte[headerBytes.Length + encryptedData.Length];
			Buffer.BlockCopy(headerBytes,0,fullRecordBytes,0,headerBytes.Length);
			Buffer.BlockCopy(encryptedData,0,fullRecordBytes,headerBytes.Length,encryptedData.Length);

			return fullRecordBytes;
		}


		/// <summary>
		/// Decrypts the given data.
		/// </summary>
		/// <param name="secret"></param>
		/// <param name="dataToDecrypt"></param>
		/// <returns></returns>
		public string Decrypt (byte[] dataToDecrypt) {
			//byte [] encryptedBytes = Encoding.ASCII.GetBytes(dataToDecrypt);
			Span<byte> spanEncryptedBytes = dataToDecrypt;

			// First 16 bytes are the EncryptInfo header
			Span<byte> spanEncryptInfoBytes = spanEncryptedBytes.Slice(0, EncryptorInfo.STORAGE_LEN);
			EncryptorInfo encryptorInfo = new EncryptorInfo(spanEncryptInfoBytes);

			// Get the EncryptionKeyVersioned Object
			EncryptionKeyVersioned encryptionKeyVersioned = GetEncryptionKeyVersioned(encryptorInfo.KeyName, encryptorInfo.Version);
			
			//Span<byte> spanEncData = spanEncryptedBytes.Slice(IVSize);
			return DecryptInternal(encryptionKeyVersioned.Secret, dataToDecrypt);
		}




		/// <summary>
		/// Performs the actual encryption of the data.  
		/// </summary>
		/// <param name="secret">The secret to be used to decrypt the data</param>
		/// <param name="dataToEncrypt">The encrypted data</param>
		/// <param name="iv">The IV that the data was encrypted with</param>
		/// <returns></returns>
		private byte[] EncryptInternal(ReadOnlySpan<byte> secret, string dataToEncrypt, byte[] iv)
		{
			if (secret.Length != EncryptionConstants.BYTE_SIZE) throw new ArgumentException("The parameter [secret] is not of the exact size required - " + EncryptionConstants.BYTE_SIZE);
			if (iv.Length != EncryptionConstants.IV_SIZE) throw new ArgumentException("The parameter [iv] is not of the exact size required - " + EncryptionConstants.IV_SIZE);


			//Create a new instance of the default Aes implementation class  and configure encryption key.  
			using Aes aes = Aes.Create();
			aes.Key = secret.ToArray();
			aes.IV = iv;

			using MemoryStream myStream = new MemoryStream();

			//Create a CryptoStream, pass it the FileStream, and encrypt it with the Aes class.  
			using CryptoStream cryptStream = new CryptoStream(myStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

			//Create a StreamWriter for easy writing to the stream
			using StreamWriter sWriter = new StreamWriter(cryptStream);

			//Write to the stream.  
			sWriter.Write(dataToEncrypt);
			sWriter.Flush();
			cryptStream.FlushFinalBlock();


			byte[] encrypted;
			encrypted = myStream.ToArray();
			return encrypted;
		}



		/// <summary>
		/// Performs the actual decryption
		/// </summary>
		/// <param name="secret"></param>
		/// <param name="encryptedData"></param>
		/// <returns></returns>
		private string DecryptInternal(ReadOnlySpan<byte> secret, byte[] encryptedData)
		{
			try
			{
				using MemoryStream myStream = new MemoryStream(encryptedData);
				byte[] encryptInfoBytes = new byte[EncryptionConstants.IV_SIZE]; 
				myStream.Read(encryptInfoBytes, 0, EncryptionConstants.IV_SIZE);

				// Convert to EncryptInfo Object
				EncryptorInfo encryptorInfo = new EncryptorInfo(encryptInfoBytes);

				//Create a new instance of the default Aes implementation class
				using Aes aes = Aes.Create();
				aes.Key = secret.ToArray();
				aes.IV = encryptorInfo.GetIV();

				
				//Create a CryptoStream, pass it the file stream, and decrypt it with the Aes class using the key and IV.
				using CryptoStream cryptStream = new CryptoStream(myStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

				//Read the stream.
				using StreamReader sReader = new StreamReader(cryptStream);
				

				string de = sReader.ReadToEnd();
				return de;
			}
			catch (System.Security.Cryptography.CryptographicException e)
			{
				System.Security.Cryptography.CryptographicException newCryptographicException =
					new CryptographicException(
						"Unable to decrypt the encrypted stream.  It may be the secret is incorrect, the IV is incorrect, the padding encoding is incorrect or the encrypted stream is wrong or corrupted.",
						e);
				throw newCryptographicException;
			}
		}

		/// <summary>
		/// Encrypts the given data, storing the 16 byte IV at the start of the stream.
		/// </summary>
		/// <param name="keyName"></param>
		/// <param name="secret">The secret for the encrypted data.</param>
		/// <param name="data"></param>
		/// <returns></returns>
		public byte [] EncryptWithStoredIV (string keyName, byte [] secret, string dataToEncrypt, byte[] iv = null) {
		if ( string.IsNullOrEmpty(keyName) ) throw new ArgumentException("The parameter [keyName] cannot be empty or null");
		if ( keyName.Length != 16 ) throw new ArgumentException("The parameter [keyName] must be exactly 16 characters in length");
		if ( secret.Length != EncryptionConstants.BYTE_SIZE ) throw new ArgumentException("The parameter [secret] is not of the exact size required - " + EncryptionConstants.BYTE_SIZE);


		using MemoryStream myStream = new MemoryStream();

		//Create a new instance of the default Aes implementation class  
		// and configure encryption key.  
		using Aes aes = Aes.Create();
		aes.Key = secret;


		//Stores IV at the beginning of the file.
		//This information will be used for decryption.
		if ( iv != null ) {
			if ( iv.Length != EncryptionConstants.IV_SIZE ) throw new ArgumentException("The parameter [iv] is not of the exact size required - " + EncryptionConstants.IV_SIZE);
		}
		else
			iv = aes.IV;
		myStream.Write(iv, 0, aes.IV.Length);

		//Create a CryptoStream, pass it the FileStream, and encrypt it with the Aes class.  
		using CryptoStream cryptStream = new CryptoStream(myStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

		//Create a StreamWriter for easy writing to the stream
		using StreamWriter sWriter = new StreamWriter(cryptStream);

		//Write to the stream.  
		//sWriter.Write(data);
		sWriter.Write(dataToEncrypt);

		sWriter.Flush();
		cryptStream.FlushFinalBlock();


		byte [] encrypted;
		encrypted = myStream.ToArray();
		return encrypted;

		//return myStream.ToArray();
	}


		public string DecryptWithStoredIV (string keyName, byte [] secret, byte [] encryptedData) {
			try {
				using MemoryStream myStream = new MemoryStream(encryptedData);

				//Create a new instance of the default Aes implementation class
				using Aes aes = Aes.Create();
				aes.Key = secret;

				//Reads IV value from beginning of the file.
				byte [] iv = new byte[aes.IV.Length];
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

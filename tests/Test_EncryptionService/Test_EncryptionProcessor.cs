using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Bogus;
using NUnit.Framework;
using NUnit.Framework.Constraints;
using SlugEnt;
using SlugEnt.Encryption.Common;
using SlugEnt.EncryptionService;
using SlugEnt.VaultEncryptor;

namespace Test_EncryptionService {
	[TestFixture]
	public class Test_EncryptionProcessor {

		// Confirms that the Bit Size is 256.
		[Test]
		public void BitSize_Correct ()
		{
			// Setup
			// Test
			// Validate
			Assert.AreEqual(256,EncryptionConstants.BIT_SIZE,"A10:");
		}


		// Tests that The Byte Size is 32 
		[Test]
		public void ByteSize_Correct ()
		{
			// Setup
			// Test
			// Validate
			Assert.AreEqual(32, EncryptionConstants.BYTE_SIZE, "A10:");
		}


		
		// Tests that The IV Size is 16
		[Test]
		public void IVSize_Correct()
		{
			// Setup
			// Test
			// Validate
			Assert.AreEqual(16, EncryptionConstants.IV_SIZE, "A10:");
		}



		/// <summary>
		/// KeyNameShort must be of exact size.
		/// </summary>
		[Test]
		public void EncryptDecrypt_InvalidKeyNameSize_Throws () {
			// Setup
			string keyName = "TooShort";
			string secret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string iv = "abcDEFGHijklmnop";
			string data = "something to encrypt";

			byte[] secretBytes = Encoding.ASCII.GetBytes(secret);
			byte[] ivBytes = Encoding.ASCII.GetBytes(iv);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();

			// Validation
			Assert.Throws<ArgumentException>(() => encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes,  data),"A10:");

			// Validate proper argument exception
			string fieldName = "characters in length";
			try { encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes, data); }
			catch (ArgumentException e)
			{
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true, "A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}



		/// <summary>
		/// KeyNameShort must not be empty.
		/// </summary>
		[Test]
		public void EncryptDecrypt_Empty_KeyName_Throws()
		{
			// Setup
			string keyName = "";
			string secret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string iv = "abcDEFGHijklmnop";
			string data = "something to encrypt";

			byte[] secretBytes = Encoding.ASCII.GetBytes(secret);
			byte[] ivBytes = Encoding.ASCII.GetBytes(iv);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();

			// Validation
			Assert.Throws<ArgumentException>(() => encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes, data), "A10:");

			// Validate proper argument exception
			string fieldName = "[keyName]";
			try { encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes, data); }
			catch ( ArgumentException e ) {
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true,"A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}



		/// <summary>
		/// KeyNameShort must not be null
		/// </summary>
		[Test]
		public void EncryptDecrypt_Null_KeyName_Throws()
		{
			// Setup
			string keyName = null;
			string secret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string iv = "abcDEFGHijklmnop";
			string data = "something to encrypt";

			byte[] secretBytes = Encoding.ASCII.GetBytes(secret);
			byte[] ivBytes = Encoding.ASCII.GetBytes(iv);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();

			// Validation
			Assert.Throws<ArgumentException>(() => encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes, data), "A10:");


			// Validate proper argument exception
			string fieldName = "[keyName]";
			try { encryptionProcessor.EncryptWithStoredIV(keyName, secretBytes,  data); }
			catch (ArgumentException e)
			{
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true, "A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);

		}


/*
		/// <summary>
		/// IV must be exact size.
		/// </summary>
		[Test]
		public void EncryptDecrypt_IV_Exact_Size()
		{
			// Setup
			string keyName = "ABCDEFGHIJKLMNOP";
			string secret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string validIV = "abcDEFGHijklmnop";
			string invalidIV = "abcdefgghh";
			string data = "something to encrypt";

			byte[] secretBytes = Encoding.ASCII.GetBytes(secret);
			byte[] validIVBytes = Encoding.ASCII.GetBytes(validIV);
			byte[] invalidIVBytes = Encoding.ASCII.GetBytes(invalidIV);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor vaultEncryptor = new EncryptionProcessor();

			// Validation
			// A. Properly sized IV passes.
			byte[]encrypted = vaultEncryptor.EncryptWithStoredIV(keyName, secretBytes,  data);
			Assert.GreaterOrEqual(encrypted.Length,0,"A10:  Encryption failed.  This should have succeeded.");

			// B. Now Invalid IV
			Assert.Throws<ArgumentException>(() => vaultEncryptor.EncryptWithStoredIV(keyName, secretBytes,  data), "A20:");

			
			// Validate proper argument exception
			string fieldName = "[iv]";
			try { vaultEncryptor.EncryptWithStoredIV(keyName, secretBytes, data); }
			catch (ArgumentException e)
			{
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true, "A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}
*/


		/// <summary>
		/// Secret must be exactly the required size.
		/// </summary>
		[Test]
		public void EncryptDecrypt_Invalid_Secret_Size_Throws()
		{
			// Setup
			string keyName = "ABCDEFGHIJKLMNOP";
			string validSecret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string invalidSecret = "abcde";
			string validIV = "abcDEFGHijklmnop";
			string data = "something to encrypt";

			byte[] validSecretBytes = Encoding.ASCII.GetBytes(validSecret);
			byte[] inValidSecretBytes = Encoding.ASCII.GetBytes(invalidSecret);
			byte[] validIVBytes = Encoding.ASCII.GetBytes(validIV);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();

			// Validation
			// A. Properly sized Secret passes.
			byte[] encrypted = encryptionProcessor.EncryptWithStoredIV(keyName, validSecretBytes, data);
			Assert.Greater(encrypted.Length, 0, "A10:  Encryption failed.  This should have succeeded.");

			// B. Now Invalid Secret
			Assert.Throws<ArgumentException>(() => encryptionProcessor.EncryptWithStoredIV(keyName, inValidSecretBytes,  data), "A20:");


			// Validate proper argument exception
			string fieldName = "[secret]";
			try { encryptionProcessor.EncryptWithStoredIV(keyName, inValidSecretBytes, data); }
			catch (ArgumentException e)
			{
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true, "A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}


		/// <summary>
		/// Encryption Should succeed.  Everything is correct.
		/// </summary>
		[Test]
		public void EncryptDecrypt_Success () {
			// Setup
			string keyName = "ABCDEFGHIJKLMNOP";
			string validSecret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string validIV = "abcDEFGHijklmnop";
			string data = "something to encrypt is written here so do it NOW";

			byte[] validSecretBytes = Encoding.ASCII.GetBytes(validSecret);
			byte[] validIVBytes = Encoding.ASCII.GetBytes(validIV);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();
			byte[] encryptedData = encryptionProcessor.EncryptWithStoredIV(keyName, validSecretBytes, data);

			encryptionProcessor.DecryptWithStoredIV(keyName, validSecretBytes, encryptedData);
			// Validate
			Assert.NotZero(encryptedData.Length,"A10:");
			Assert.Greater(encryptedData.Length,data.Length, "A20:");
		}


		[Test]
		public void En2 () {
			string keyName = "ABCDEFGHIJKLMNOP";
			string validSecret = "abcDEFGHijklmnopabcDEFGHijklmnop";
			string validIV = "abcDEFGHijklmnop";
			string data = "something to encrypt is written here so do it NOW";
			
			byte[] validSecretBytes = Encoding.ASCII.GetBytes(validSecret);
			byte[] validIVBytes = Encoding.ASCII.GetBytes(validIV);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);

			//validIVBytes = null;
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();
			byte[] enc = encryptionProcessor.EncryptWithStoredIV(keyName,validSecretBytes,data);
			//byte[] enc = encryptionProcessor.Encrypt3();

			string dec = encryptionProcessor.DecryptWithStoredIV(keyName, validSecretBytes,enc);
			Assert.AreEqual(data,dec,"A10:");
			//encryptionProcessor.Decrypt3(enc);
		}



		/*

		/// <summary>
		/// Encryption Should succeed.  Everything is correct.
		/// </summary>
		[Test]
		public void EncryptDecrypt_Span_Success()
		{
			// Setup
			ushort version = 2; 
			string keyID = "ABCD";
			DateTime LastUpdated = DateTime.Now;
			

			string keyName = "ABCDEFGHIJKLMNOP";
			string validSecret = "abcDEFGHijklmnopqrstuvwxyz123456";
			string data = "something to encrypt is written here so do it NOW";

			ReadOnlySpan<byte> validSecretBytes = Encoding.ASCII.GetBytes(validSecret);
			byte[] dataBytes = Encoding.ASCII.GetBytes(data);

			// Test
			EncryptorInfo encryptorInfo = new EncryptorInfo(keyID,version,LastUpdated);
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();

			
			byte[] encryptedData = encryptionProcessor.Encrypt(encryptorInfo,validSecretBytes,data);

			string msg = encryptionProcessor.Decrypt(encryptedData);
			Assert.AreEqual(data,msg,"A10:  Encrypted contents are invalid:");

			//encryptionProcessor.DecryptWithStoredIV(keyName, validSecretBytes, encryptedData);
			// Validate
			Assert.NotZero(encryptedData.Length, "A10:");
			Assert.Greater(encryptedData.Length, data.Length, "A20:");
		}
		*/

		// Validate we can retrieve a Secret of the requested version.
		[Test]
		public void GetEncryptionKeyVersioned_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			string KeyName = "abcd";
			TimeUnit ttl = new TimeUnit("3d");
			ushort updatedVersionNumber = 2454;

			// Create a number of EncryptionKeyVersioned objects.
			EncryptionKeyVersioned enc1 = new EncryptionKeyVersioned( KeyName, ttl);
			EncryptionKeyVersioned enc2 = enc1.NewVersion();
			EncryptionKeyVersioned enc3 = enc2.NewVersion();
			EncryptionKeyVersioned enc4 = enc3.NewVersion(4000);
			EncryptionKeyVersioned enc5 = enc4.NewVersion(5000);
			EncryptionKeyVersioned enc6 = enc5.NewVersion(6000);

			// Add to the EncryptionProcessor Keyring
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();
			encryptionProcessor.LoadEncyptionKey(enc1);
			encryptionProcessor.LoadEncyptionKey(enc2);
			encryptionProcessor.LoadEncyptionKey(enc3);
			encryptionProcessor.LoadEncyptionKey(enc4);
			encryptionProcessor.LoadEncyptionKey(enc5);
			encryptionProcessor.LoadEncyptionKey(enc6);

			// Test
			// Now Retrieve requested object
			EncryptionKeyVersioned encryptionKeyVersioned = encryptionProcessor.GetEncryptionKeyVersioned(enc1.KeyNameShort, 5000);
			ReadOnlySpan<byte> secret = encryptionKeyVersioned.Secret;

			// Validate
			Assert.AreEqual(enc5.Secret.ToArray(), secret.ToArray(), "A10: Secrets are not the same");
		}



		// Validate entire Add KeyRing, Add EncryptionKeyVersioned, Encrypt Data, Decrypt Data.  With just a single EncryptionKeyVersioned object in KeyRing
		[Test]
		public void EncryptDecrypt_Simple_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			string KeyName = "1969";
			TimeUnit ttl = new TimeUnit("3w");
			string data = "The first encryption data message!";

			// Create a number of EncryptionKeyVersioned objects.
			EncryptionKeyVersioned enc1 = new EncryptionKeyVersioned( KeyName, ttl);


			// Test
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();
			encryptionProcessor.LoadEncyptionKey(enc1);
			byte[] dataEncrypted = encryptionProcessor.Encrypt(KeyName, data);

			// Validate
			string dataDecrypted = encryptionProcessor.Decrypt(dataEncrypted);

			Assert.AreEqual(data, dataDecrypted,"A10: ");
		}




		// Validate entire Add KeyRing, Add EncryptionKeyVersioned, Encrypt Data, Decrypt Data.  This test is similar to Simple version, but
		// has a keyring with multiple keynames with multiple versions.
		[Test]
		public void EncryptDecrypt_Complex_Success () {
			// Setup
			Faker faker = new Faker();
			List<KeyRing_sample> keyRingTest = new List<KeyRing_sample>();
			EncryptionProcessor encryptionProcessor = new EncryptionProcessor();
			TimeUnit ttl = new TimeUnit("3w");
			

			// Determine how many Keynames we will utilize
			Random random = new Random();
			int numKeynames = random.Next(10, 25);


			// Test - we will run thru 10 - 25 random keynames, each with 10 - 100 versions, each with a random 20% sampling to perform
			// actual encryption / decryption test on.
			for ( int i = 0; i < numKeynames; i++ ) {
				Guid appID = Guid.NewGuid();

				// Get unique keyname
				string keyName = "";
				bool generateNewKey = true;
				while ( generateNewKey ) {
					keyName = GenerateRandomKeyName();
					if ( !encryptionProcessor.KeyNameExists(keyName) ) generateNewKey = false;
				}

				// Now we will add a random number of EncryptionKeyVersioned objects and randomly select a sample of those to actually encrypt data with.
				int numVersions = random.Next(10, 100);
				EncryptionKeyVersioned encryptionKeyVersioned = null;
				for ( int j = 0; j < numVersions; j++ ) {
					int createEncryptedDataRand = random.Next(1, 5);
					bool createEncryptedData = false;
					if ( createEncryptedDataRand == 3 ) createEncryptedData = true;

					// Create the EncryptionKeyVersioned object.  If null then it is first one of this key.  If not null then increment version.
					if ( encryptionKeyVersioned is null )
						encryptionKeyVersioned = new EncryptionKeyVersioned( keyName, ttl);
					else
						encryptionKeyVersioned = encryptionKeyVersioned.NewVersion();

					// Load the EncKeyVer to Processor.
					encryptionProcessor.LoadEncyptionKey(encryptionKeyVersioned);

					// If this record has been selected to be encrypted, then encrypt and add to list of items to test.
					string data = "";
					if ( createEncryptedData ) {
						data = faker.Lorem.Sentence();

						encryptionProcessor.LoadEncyptionKey(encryptionKeyVersioned);

						// Add to the list to test for decryption.
						KeyRing_sample sample = new KeyRing_sample();
						sample.dataOriginal = data;
						sample.keyName = encryptionKeyVersioned.KeyNameShort;
						sample.version = encryptionKeyVersioned.Version;

						// Encrypt 
						sample.dataEncrypted = encryptionProcessor.Encrypt(encryptionKeyVersioned.KeyNameShort, data);
						keyRingTest.Add(sample);
					}
				}
			}
			// Validate
			foreach (KeyRing_sample sample in keyRingTest)
			{
				string dataDecrypted = encryptionProcessor.Decrypt(sample.dataEncrypted);
				Assert.AreEqual(sample.dataOriginal, dataDecrypted,
				                "A10: KeyName [" +
				                sample.keyName +
				                "]  Version [" +
				                sample.version +
				                "]  OrigData [ " +
				                sample.dataOriginal +
				                "]  DecryptedData [" +
				                dataDecrypted +
				                "]");
				TestContext.WriteLine("Successful Decryption:   KeyName [" +
				                      sample.keyName +
				                      "]  Version [" +
				                      sample.version +
				                      "]  OrigData [ " +
				                      sample.dataOriginal);
			}

		}




		/// <summary>
		/// Builds a unique 4 character keyname
		/// </summary>
		/// <returns></returns>
		private string GenerateRandomKeyName () {
			Random random= new Random();
			StringBuilder s = new StringBuilder();
			for ( int i = 0; i < 2; i++ ) {
				// 1st char
				int charValue = random.Next(65, 90);
				s.Append(Convert.ToChar(charValue));

				// 2nd char
				charValue = random.Next(97, 122);
				s.Append(Convert.ToChar(charValue));
			}

			return s.ToString();
		}
	}
}
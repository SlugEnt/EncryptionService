using System;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Constraints;
using SlugEnt.VaultEncryptor;

namespace Test_EncryptionService {
	[TestFixture]
	public class Test_VaultEncryptor {

		// Confirms that the Bit Size is 256.
		[Test]
		public void BitSize_Correct ()
		{
			// Setup
			// Test
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validate
			Assert.AreEqual(256,vaultEncryptor.BitSize,"A10:");
		}


		// Tests that The Byte Size is 32 
		[Test]
		public void ByteSize_Correct ()
		{
			// Setup
			// Test
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validate
			Assert.AreEqual(32, vaultEncryptor.ByteSize, "A10:");
		}


		/*
		// Tests that The IV Size is 16
		[Test]
		public void IVSize_Correct()
		{
			// Setup
			// Test
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validate
			Assert.AreEqual(16, vaultEncryptor.IVSize, "A10:");
		}
*/


		/// <summary>
		/// KeyName must be of exact size.
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validation
			Assert.Throws<ArgumentException>(() => vaultEncryptor.Encrypt(keyName, secretBytes,  data),"A10:");

			// Validate proper argument exception
			string fieldName = "characters in length";
			try { vaultEncryptor.Encrypt(keyName, secretBytes, data); }
			catch (ArgumentException e)
			{
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true, "A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}



		/// <summary>
		/// KeyName must not be empty.
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validation
			Assert.Throws<ArgumentException>(() => vaultEncryptor.Encrypt(keyName, secretBytes, data), "A10:");

			// Validate proper argument exception
			string fieldName = "[keyName]";
			try { vaultEncryptor.Encrypt(keyName, secretBytes, data); }
			catch ( ArgumentException e ) {
				Assert.IsTrue(e.Message.Contains(fieldName));
				return;
			}

			// This will always error.  If we are here, then the test did not run properly
			Assert.IsFalse(true,"A10: An exception was thrown, but not the one we were expecting.  Expecting ArgumentException with a field of " + fieldName);
		}



		/// <summary>
		/// KeyName must not be null
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validation
			Assert.Throws<ArgumentException>(() => vaultEncryptor.Encrypt(keyName, secretBytes, data), "A10:");


			// Validate proper argument exception
			string fieldName = "[keyName]";
			try { vaultEncryptor.Encrypt(keyName, secretBytes,  data); }
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validation
			// A. Properly sized IV passes.
			byte[]encrypted = vaultEncryptor.Encrypt(keyName, secretBytes,  data);
			Assert.GreaterOrEqual(encrypted.Length,0,"A10:  Encryption failed.  This should have succeeded.");

			// B. Now Invalid IV
			Assert.Throws<ArgumentException>(() => vaultEncryptor.Encrypt(keyName, secretBytes,  data), "A20:");

			
			// Validate proper argument exception
			string fieldName = "[iv]";
			try { vaultEncryptor.Encrypt(keyName, secretBytes, data); }
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();

			// Validation
			// A. Properly sized Secret passes.
			byte[] encrypted = vaultEncryptor.Encrypt(keyName, validSecretBytes, data);
			Assert.Greater(encrypted.Length, 0, "A10:  Encryption failed.  This should have succeeded.");

			// B. Now Invalid Secret
			Assert.Throws<ArgumentException>(() => vaultEncryptor.Encrypt(keyName, inValidSecretBytes,  data), "A20:");


			// Validate proper argument exception
			string fieldName = "[secret]";
			try { vaultEncryptor.Encrypt(keyName, inValidSecretBytes, data); }
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();
			byte[] encryptedData = vaultEncryptor.Encrypt(keyName, validSecretBytes, data);

			vaultEncryptor.Decrypt(keyName, validSecretBytes, encryptedData);
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
			VaultEncryptor vaultEncryptor = new VaultEncryptor();
			byte[] enc = vaultEncryptor.Encrypt(keyName,validSecretBytes,data);
			//byte[] enc = vaultEncryptor.Encrypt3();

			string dec = vaultEncryptor.Decrypt(keyName, validSecretBytes,enc);
			Assert.AreEqual(data,dec,"A10:");
			//vaultEncryptor.Decrypt3(enc);
		}
	}
}
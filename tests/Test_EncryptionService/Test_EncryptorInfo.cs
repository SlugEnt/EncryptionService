using System;
using System.Data.Common;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Constraints;
using SlugEnt.VaultEncryptor;


namespace Test_EncryptionService
{
	[TestFixture]
	class Test_EncryptorInfo
	{

		[TestCase("AB")]
		[TestCase("ABcdefghhyhgy")]
		[TestCase("")]
		[TestCase(null)]
		[Test]
		public void KeyName_IncorrectSize_Throws (string keyName) {
			// Setup
			EncryptorInfo encryptorInfo = new EncryptorInfo();

			// Test & Validate
			Assert.Throws<ArgumentException>( () => encryptorInfo.KeyName = keyName,"A10:  Should have thrown an Argument Exception");
		}





		[Test]
		public void KeyName_Success () {
			// Setup
			string keyName = "ABCd";
			EncryptorInfo encryptorInfo  = new EncryptorInfo();
			Byte[] original = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage, 0, original, 0, EncryptorInfo.STORAGE_LEN);


			// Test
			encryptorInfo.KeyName = keyName;

			// Validate
			Assert.AreEqual(keyName,encryptorInfo.KeyName,"A10:");

			// Test the Storage block to make sure it is correct.
			// Get the updated storage array so we can compare against original			
			Byte[] updated = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage, 0, updated, 0, EncryptorInfo.STORAGE_LEN);

			// Test that name placed in correct area.
			string internalKeyName =  Encoding.ASCII.GetString(updated,EncryptorInfo.KEYNAME_START,EncryptorInfo.KEYNAME_LENGTH);
			Assert.AreEqual(keyName,internalKeyName,"A20:");


			// Ensure all bytes after the KeyName are empty.
			int index = EncryptorInfo.KEYNAME_START + EncryptorInfo.KEYNAME_LENGTH;
			int length = EncryptorInfo.STORAGE_LEN - (EncryptorInfo.KEYNAME_START + EncryptorInfo.KEYNAME_LENGTH);
			string after = Encoding.ASCII.GetString(updated, index, length);
			string orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig, after, "A30:  The storage array after the Version Bytes has been updated.  There should have been no changes to these bytes");


			string afterKeyName = Encoding.ASCII.GetString(updated, EncryptorInfo.KEYNAME_LENGTH, EncryptorInfo.STORAGE_LEN - EncryptorInfo.KEYNAME_LENGTH);
			string origAfterKeyName = Encoding.ASCII.GetString(original, EncryptorInfo.KEYNAME_LENGTH, EncryptorInfo.STORAGE_LEN - EncryptorInfo.KEYNAME_LENGTH);
			Assert.AreEqual(origAfterKeyName,afterKeyName,"A30:");
		}


		[TestCase((ushort)23)]
		[TestCase((ushort)65535)]
		[TestCase((ushort)0)]
		[Test]
		public void Version_Success (ushort version) {
			// Setup
			EncryptorInfo encryptorInfo = new EncryptorInfo();
			Byte[] original = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage, 0, original, 0, EncryptorInfo.STORAGE_LEN);


			// Test
			encryptorInfo.Version = version;

			// Validate
			Assert.AreEqual(version, encryptorInfo.Version, "A10:");

			// Get the updated storage array so we can compare against original			
			Byte[] updated = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage, 0, updated, 0, EncryptorInfo.STORAGE_LEN);


			// Ensure all bytes before the version are empty.
			int index = 0;
			int length = EncryptorInfo.KEYNAME_LENGTH;
			string after = Encoding.ASCII.GetString(updated, index, length);
			string orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig,after,"A20:  The storage array before the Version bytes has been updated.  There should have been no change to these bytes");

			// Ensure all bytes after the Version are empty.
			index = EncryptorInfo.VER_START + EncryptorInfo.VER_LENGTH;
			length = EncryptorInfo.STORAGE_LEN - EncryptorInfo.VER_LENGTH - EncryptorInfo.KEYNAME_LENGTH;
			after = Encoding.ASCII.GetString(updated, index,length);
			orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig, after, "A30:  The storage array after the Version Bytes has been updated.  There should have been no changes to these bytes");
		}


		[TestCase(1,"Now")]
		[TestCase(2, "Minimum Date")]
		[TestCase(3, "Maximum Date")]
		[Test]
		public void LastUpdated_Success(int caseNumber, string name)
		{
			// Setup
			DateTime dateTime = DateTime.Now;

			if ( caseNumber == 2 )
				dateTime = DateTime.MinValue;
			else if (caseNumber == 3) dateTime = DateTime.MaxValue;

			EncryptorInfo encryptorInfo = new EncryptorInfo();
			Byte[] original = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage,0,original,0,EncryptorInfo.STORAGE_LEN);
			

			// Test
			encryptorInfo.LastUpdated = dateTime;

			// Validate
			Assert.AreEqual(dateTime, encryptorInfo.LastUpdated, "A10: Error running case " + caseNumber + " - Name: " + name);

			// Get the updated storage array so we can compare against original			
			Byte[] updated = new byte[EncryptorInfo.STORAGE_LEN];
			Buffer.BlockCopy(encryptorInfo._storage, 0, updated, 0, EncryptorInfo.STORAGE_LEN);

			// Ensure all bytes before the version are empty.
			int index = 0;
			int length = EncryptorInfo.TIME_START;
			string after = Encoding.ASCII.GetString(updated, index, length);
			string orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig, after, "A20:  The storage array before the LastUpdated bytes has been updated.  There should have been no change to these bytes");

			// Ensure all bytes after the Version are empty.
			index = EncryptorInfo.TIME_START + EncryptorInfo.TIME_LENGTH;
			length = EncryptorInfo.STORAGE_LEN - (EncryptorInfo.TIME_START + EncryptorInfo.TIME_LENGTH);
			after = Encoding.ASCII.GetString(updated, index, length);
			orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig, after, "A30:  The storage array after the LastUpdated Bytes has been updated.  There should have been no changes to these bytes");
		}
	}
}

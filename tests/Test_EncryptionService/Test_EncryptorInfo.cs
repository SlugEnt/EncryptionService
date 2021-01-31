﻿using System;
using System.Data.Common;
using System.Net.Security;
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


			// Ensure all bytes after the KeyNameShort are empty.
			int index = EncryptorInfo.KEYNAME_START + EncryptorInfo.KEYNAME_LENGTH;
			int length = EncryptorInfo.STORAGE_LEN - (EncryptorInfo.KEYNAME_START + EncryptorInfo.KEYNAME_LENGTH);
			string after = Encoding.ASCII.GetString(updated, index, length);
			string orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig, after, "A30:  The storage array after the Version Bytes has been updated.  There should have been no changes to these bytes");
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
			int length = EncryptorInfo.KEYNAME_START + EncryptorInfo.KEYNAME_LENGTH;
			string after = Encoding.ASCII.GetString(updated, index, length);
			string orig = Encoding.ASCII.GetString(original, index, length);
			Assert.AreEqual(orig,after,"A20:  The storage array before the Version bytes has been updated.  There should have been no change to these bytes");

			// Ensure all bytes after the Version are empty.
			index = EncryptorInfo.VER_START + EncryptorInfo.VER_LENGTH;
			length = EncryptorInfo.STORAGE_LEN - (EncryptorInfo.VER_LENGTH + EncryptorInfo.VER_START);
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


		// Ensure the RecordIdentifier is correct and has not changed
		[Test]
		public void RecordIdentifier_CorrectValue_OnCreation () {
			EncryptorInfo encryptor = new EncryptorInfo();
			Assert.AreEqual(EncryptorInfo.RECORD_IDENTIFIER_VALUE,encryptor.RecordIdentifier,"A10:  The Record Identifier as a short must match the byte array.  One of these has changed.  This can be a detrimental change to existing encrypted objects.  Ensure the change was warranted and you have a plan to deal with existing encrypted objects as they will no longer work with this new code base");

			// This just confirms the value is the original value when this class was created.  Changing this value will guarantee exiting encrypted objects will not be able to be decrypted with the new version of this class.
			Assert.AreEqual(43275, encryptor.RecordIdentifier, "A10:  The Record Identifier as a short must match the byte array.  One of these has changed.  This can be a detrimental change to existing encrypted objects.  Ensure the change was warranted and you have a plan to deal with existing encrypted objects as they will no longer work with this new code base");
		}


		[Test]
		public void Constructor_ExistingData_Success () {
			// Setup - Create an encryptor
			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.KeyName = "abGT";
			encryptor.Version = 1;
			encryptor.LastUpdated = DateTime.Now;


			byte [] createdEncryptorBytes = encryptor.GetAsBytes();

			// Test - Create a new encryptor from the existing.
			EncryptorInfo newEncryptorInfo = new EncryptorInfo(createdEncryptorBytes);

			// Validate
			Assert.AreEqual(encryptor.RecordIdentifier, newEncryptorInfo.RecordIdentifier,"A10:");
			Assert.AreEqual(encryptor.KeyName,newEncryptorInfo.KeyName,"A20:");
			Assert.AreEqual(encryptor.Version,newEncryptorInfo.Version,"A30:");
			Assert.AreEqual(encryptor.LastUpdated,newEncryptorInfo.LastUpdated,"A40:");
			Assert.AreEqual(true,newEncryptorInfo.IsEncryptorInfo,"A100:");
		}


		// Invalid byte stream with incorrect Record Header Identifier throws error.
		[Test]
		public void Constructor_InvalidExistingData_IsEncryptorInfo_False () {
			byte [] existingBytes = new byte[] {0x65, 0x56, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x15};
			Assert.Throws<ArgumentException> (() => new EncryptorInfo(existingBytes),"A10:");
		}



		// Validates Bytes and AsBytes yield same result.
		[Test]
		public void GetBytes_Equals_GetAsBytes () {
			// Setup - Create an encryptor
			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.KeyName = "1954";
			encryptor.Version = 464;
			encryptor.LastUpdated = DateTime.Now;

			// Test
			byte [] asBytes = encryptor.GetAsBytes();
			byte [] bytes = encryptor.GetBytes();

			// Validate
			Assert.AreEqual(bytes,asBytes,"A10:  The 2 arrays should have been exactly equal");

		}


		[Test]
		public void GetAsBytes_DoesNotChange_InternalStorage () {
			// Setup - Create an encryptor
			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.KeyName = "1954";
			encryptor.Version = 464;
			encryptor.LastUpdated = DateTime.Now;
			byte[] origBytes = encryptor.GetBytes();

			// Test
			byte[] asBytes = encryptor.GetAsBytes();
			asBytes[4] = 0x19;
			asBytes[13] = 0xA2;


			// Validate
			byte[] bytes = encryptor.GetBytes();
			Assert.AreNotEqual(bytes, asBytes, "A20:  The 2 arrays should have not been equal.");
			Assert.AreEqual(origBytes,bytes,"A30: The underlying byte array for EncryptorInfo should never be able to be changed externally");

		}



		// Ensure the IVDateTime Function has not changed and returns the correct data.
		[TestCase("A - 2021/01/11 22:14:45",637460000850000000, 1275225934190000000)]
		[TestCase("B - 2023/12/10 10:14:12", 638378000520000000, 1311488430140000000)]
		[TestCase("C - 2027/07/16 2:33:57", 639513020370000000, 1309467265410000000)]
		[TestCase("D - 2036/08/05 7:01:04", 642371292640000000, 1295914718210000000)]
		[TestCase("E - 2052/04/27 15:30:45", 647649774450000000, 1321074699150000000)]
		[Test]
		public void GetIVDateTime_Success (string caseName, long origTicks, long expectedIVTicks) {
			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.LastUpdated = new DateTime(origTicks);

			DateTime ivDateTime = encryptor.GetIvDateTime();

			long tickIV = ivDateTime.Ticks;

			Assert.AreEqual(expectedIVTicks, tickIV, "A10: Case Failed [" + caseName + "]");
		}


		[Test]
		public void GetIV_Success () {
			// Setup
			byte[] ivBytes = new byte[16];

			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.LastUpdated = DateTime.Now;
			DateTime ivDateTime = encryptor.GetIvDateTime();


			// Build the IV as we expect it.
			// Get New Computed IV Time Value and add to buffer.
			byte[] time = BitConverter.GetBytes(ivDateTime.Ticks);
			Buffer.BlockCopy(time, 0, ivBytes, 0, 8);


			// Now get LastUpdated and copy it to buffer
			byte[] lastupTime = BitConverter.GetBytes(encryptor.LastUpdated.Ticks);
			Buffer.BlockCopy(lastupTime, 0, ivBytes, 8, 8);

			byte [] recBytes = encryptor.GetIV();
			Assert.AreEqual(ivBytes,recBytes,"A10:  The IV value is incorrect.");
		}


		[Test]
		public void Constructor_WithSpan () {
			// Setup - Create an encryptor
			EncryptorInfo encryptor = new EncryptorInfo();
			encryptor.KeyName = "abGT";
			encryptor.Version = 1;
			encryptor.LastUpdated = DateTime.Now;


			byte[] createdEncryptorBytes = encryptor.GetAsBytes();
			Span<byte> spanCreatedEncryptoBytes = new Span<byte>(createdEncryptorBytes);
			
			// Test - Create a new encryptor from the existing.
			EncryptorInfo newEncryptorInfo = new EncryptorInfo(spanCreatedEncryptoBytes);

			// Validate
			Assert.AreEqual(encryptor.RecordIdentifier, newEncryptorInfo.RecordIdentifier, "A10:");
			Assert.AreEqual(encryptor.KeyName, newEncryptorInfo.KeyName, "A20:");
			Assert.AreEqual(encryptor.Version, newEncryptorInfo.Version, "A30:");
			Assert.AreEqual(encryptor.LastUpdated, newEncryptorInfo.LastUpdated, "A40:");
			Assert.AreEqual(true, newEncryptorInfo.IsEncryptorInfo, "A100:");

		}
	}
}

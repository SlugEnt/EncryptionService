using NUnit.Framework;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework.Internal;
using SlugEnt;
using SlugEnt.Encryption.Common;
using SlugEnt.EncryptionService;


namespace Test_EncryptionService
{
	[TestFixture]
	public class Test_EncryptionKeyVersioned
	{
		[Test]
		public void Constructor_AutoSecret_Success()
		{
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;

			// Testing
			EncryptionKeyVersioned encVersioned = new EncryptionKeyVersioned(appID, keyNameShort, ttl);


			// Validation
			Assert.AreEqual(appID,encVersioned.ApplicationId,"A10: ");
			Assert.AreEqual(keyNameShort,encVersioned.KeyNameShort, "A15: ");
			Assert.AreEqual(ttl,encVersioned.TTL,"A20: ");

			// Has an ID.
			Assert.IsNotEmpty(encVersioned.Id.ToString(),"A30: ");

			// Secret must be 32 characters
			Assert.AreEqual(EncryptionConstants.BYTE_SIZE, encVersioned.Secret.Length,"A40: ");

			// Version must be 1
			Assert.AreEqual(1, encVersioned.Version, "A50: ");

			// Status
			Assert.AreEqual(EnumEncryptionKeyStatus.Current, encVersioned.Status,"A60: ");

			// Created At 
			Assert.GreaterOrEqual(encVersioned.CreatedAt, recentTime,"A90:");

			// Last Accessed At
			Assert.AreEqual(encVersioned.CreatedAt,encVersioned.LastRequestedAt,"A100: ");
		}



		/// <summary>
		/// The Keyname must be exactly 4 characters
		/// </summary>
		[TestCase("abC")]
		[TestCase("abCDEFG")]
		[Test]
		public void Constructor_KeyNameInvalid_Throws (string keyname) {
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");

			// Testing / Validation
			Assert.Throws<ArgumentException> (() => new EncryptionKeyVersioned(appID, keyname, ttl), "A10: ");
		}



		[Test]
		public void SetSecret_WithString_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;

			string secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

			// Testing
			EncryptionKeyVersioned encVersioned = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			encVersioned.SetSecret(secret);


			// Validation
			ReadOnlySpan<byte> secretValue = encVersioned.Secret;
			string secretReturn = Encoding.ASCII.GetString(secretValue);
			Assert.AreEqual(secret,secretReturn,"A10: ");
		}


		[TestCase("ABCDEFGHIJKLMNOPQRSTUVWXYZabcde")]
		[TestCase("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefG")]
		[Test]
		public void SetSecret_WithString_InvalidLength_Throws (string secret) {
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;


			// Testing
			EncryptionKeyVersioned encVersioned = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			Assert.Throws<ArgumentException>(() => encVersioned.SetSecret(secret), "A10: ");
		}


		public void SetSecret_WithBytes_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;

			RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
			byte[] randomBytes = new byte[EncryptionConstants.BYTE_SIZE];

			// Testing
			EncryptionKeyVersioned encVersioned = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			encVersioned.SetSecret(randomBytes);


			// Validation
			ReadOnlySpan<byte> secretValue = encVersioned.Secret;
			
			Assert.AreEqual(randomBytes,secretValue.Length,"A10:  Arrays have different lengths");
			
			Assert.AreEqual(randomBytes, secretValue.ToArray(), "A20: ");
		}


		[TestCase(31)]
		[TestCase(33)]
		[Test]
		public void SetSecret_WithBytes_InvalidLength_Throws (int length) {
			// Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;

			RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
			byte[] randomBytes = new byte[length];

			// Testing
			EncryptionKeyVersioned encVersioned = new EncryptionKeyVersioned(appID, keyNameShort, ttl);

			//Validation
			Assert.Throws<ArgumentException>(() => encVersioned.SetSecret(randomBytes), "A10:");
		}


		/// <summary>
		/// Validates BuildID works
		/// </summary>
		/// <param name="key"></param>
		/// <param name="doValidation"></param>
		[TestCase("abcd",true)]
		[TestCase("abcd",false)]
		[Test]
		public void BuildId_Success (string key, bool doValidation) {
			// Setup
			ushort versionNum = 564;

			// Test
			string result = EncryptionKeyVersioned.BuildID(key, versionNum, doValidation);


			//Validate
			string expected = key + versionNum.ToString();
			Assert.AreEqual(expected,result,"A10: ");
		}



		/// <summary>
		/// Validates BuildID works
		/// </summary>
		/// <param name="key"></param>
		/// <param name="doValidation"></param>
		[TestCase("ad", true)]
		[TestCase("ad", false)]
		[Test]
		public void BuildId_InvalidKey_Throws(string key, bool doValidation)
		{
			// Setup
			ushort versionNum = 563;

			// Test
			//Validate
			Assert.Throws<ArgumentException>(() => EncryptionKeyVersioned.BuildID(key, versionNum, doValidation), "A10: ");
		}


		[Test]
		public void Equals_Success () {
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			DateTime recentTime = DateTime.Now;


			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID,keyNameShort,ttl );
			EncryptionKeyVersioned b = new EncryptionKeyVersioned(appID, keyNameShort, ttl);

			// Validate
			Assert.IsTrue(a == b,"A10: ");
		}



		[Test]
		public void NotEquals_KeyNameDiff_Success()
		{
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			string key2 = "zxya";
			DateTime recentTime = DateTime.Now;


			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			EncryptionKeyVersioned b = new EncryptionKeyVersioned(appID, key2, ttl);

			// Validate
			Assert.IsTrue(a != b, "A10: ");
			Assert.IsFalse(a == b, "A20: ");
		}

		[Test]
		public void NotEquals_AppIDDiff_Success()
		{
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			Guid appID2 = Guid.NewGuid();
			DateTime recentTime = DateTime.Now;


			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			EncryptionKeyVersioned b = new EncryptionKeyVersioned(appID2, keyNameShort, ttl);

			// Validate
			Assert.IsTrue(a != b, "A10: ");
			Assert.IsFalse(a == b, "A20: ");
		}



		[Test]
		public void NotEquals_VersionDiff_Success()
		{
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			ushort version2 = 4;

			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID, keyNameShort, ttl);
			EncryptionKeyVersioned b = a.NewVersion();


			// Validate
			Assert.IsTrue(a != b, "A10: ");
			Assert.IsFalse(a == b, "A20: ");
		}


		[Test]
		public void NewVersion_WithIncrement_Success () {
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";

			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID, keyNameShort, ttl);

			// Test
			EncryptionKeyVersioned b = a.NewVersion();

			// Validate
			Assert.AreEqual(a.ApplicationId,b.ApplicationId,"A10:");
			Assert.AreEqual(a.KeyNameShort, b.KeyNameShort, "A20: ");

			ushort newVersion = (ushort) (a.Version + 1);
			Assert.AreEqual(newVersion,b.Version, "A30: ");
		}




		[Test]
		public void NewVersion_WithVersionSpecified_Success()
		{
			//Setup
			Guid appID = Guid.NewGuid();
			TimeUnit ttl = new TimeUnit("5d");
			string keyNameShort = "ABcd";
			ushort newVersion = 245;

			EncryptionKeyVersioned a = new EncryptionKeyVersioned(appID, keyNameShort, ttl);

			// Test
			EncryptionKeyVersioned b = a.NewVersion(newVersion);

			// Validate
			Assert.AreEqual(a.ApplicationId, b.ApplicationId, "A10:");
			Assert.AreEqual(a.KeyNameShort, b.KeyNameShort, "A20: ");
			Assert.AreEqual(newVersion, b.Version, "A30: ");
		}
	}
}

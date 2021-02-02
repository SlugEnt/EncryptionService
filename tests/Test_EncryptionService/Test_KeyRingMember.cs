using System;
using NUnit.Framework;
using SlugEnt;
using SlugEnt.EncryptionService;
using SlugEnt.VaultEncryptor;

namespace Test_EncryptionService {
	[TestFixture]
	public class Test_KeyRingMember {

		[Test]
		public void Constructor_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			string KeyName = "abcd";
			TimeUnit ttl = new TimeUnit("3d");
			
			EncryptionKeyVersioned encryptionKeyVersioned = new EncryptionKeyVersioned(appID, KeyName,ttl);

			// Test
			KeyRingMember keyRingMember = new KeyRingMember(encryptionKeyVersioned);

			// Validate 
			EncryptionKeyVersioned stored = keyRingMember.CurrentKey;

			Assert.AreEqual(encryptionKeyVersioned, stored, "A10: ");
			Assert.AreEqual(KeyName,keyRingMember.KeyName,"A10:");
			Assert.AreEqual(encryptionKeyVersioned.Version,keyRingMember.CurrentVersionNumber,"A20: ");
		}


		[Test]
		public void CurrentVersion_Success () {
			// Setup
			Guid appID = Guid.NewGuid();
			string KeyName = "abcd";
			TimeUnit ttl = new TimeUnit("3d");
			ushort updatedVersionNumber = 2454;

			EncryptionKeyVersioned encryptionKeyVersioned = new EncryptionKeyVersioned(appID, KeyName, ttl);
			EncryptionKeyVersioned laterVersion = encryptionKeyVersioned.NewVersion(updatedVersionNumber);

			KeyRingMember keyRingMember = new KeyRingMember(encryptionKeyVersioned);
			keyRingMember.InsertVersion(laterVersion);

			// Test
			// Validate 
			EncryptionKeyVersioned stored = keyRingMember.CurrentKey;
			Assert.AreEqual(updatedVersionNumber,keyRingMember.CurrentVersionNumber);
		}




		[Test]
		public void InsertVersion_Success()
		{
			// Setup
			Guid appID = Guid.NewGuid();
			string KeyName = "abcd";
			TimeUnit ttl = new TimeUnit("3d");
			ushort updatedVersionNumber = 2021;

			EncryptionKeyVersioned encryptionKeyVersioned = new EncryptionKeyVersioned(appID, KeyName, ttl);
			EncryptionKeyVersioned laterVersion = encryptionKeyVersioned.NewVersion(updatedVersionNumber);

			KeyRingMember keyRingMember = new KeyRingMember(encryptionKeyVersioned);
			keyRingMember.InsertVersion(laterVersion);


			// Test
			// Validate 
			EncryptionKeyVersioned stored = keyRingMember.CurrentKey;
			Assert.AreEqual(updatedVersionNumber, keyRingMember.CurrentVersionNumber,"A10: ");
			Assert.AreEqual(laterVersion,stored,"A20:  They should have been same object");
			Assert.AreEqual(2,keyRingMember.UT_VersionKeyDict().Count,"A30: Dictionary should have had 2 items.");
		}
	}
}
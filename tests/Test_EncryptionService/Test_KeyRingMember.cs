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
			Guid appID = new Guid();
			string KeyName = "abcd";
			TimeUnit ttl = new TimeUnit("3d");
			
			EncryptionKeyVersioned encryptionKeyVersioned = new EncryptionKeyVersioned(appID, KeyName,ttl);

			// Test
			KeyRingMember keyRingMember = new KeyRingMember(encryptionKeyVersioned);

			// Validate 
			Assert.AreEqual(KeyName,keyRingMember.KeyName,"A10:");
			
			
		}
	}
}
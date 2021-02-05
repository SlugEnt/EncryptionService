using NUnit.Framework;
using SlugEnt;
using SlugEnt.EncryptionService;


namespace Test_EncryptionService
{
	[TestFixture]
	public class Test_AppKeyRingMember
	{
		[Test]
		public void Constructor_Success () {
			// Setup
			string keyName = "abXY";
			string desc = "some text";
			TimeUnit ttl = new TimeUnit("3d");

			// Test
			AppKeyRingMember appKeyRingMember = new AppKeyRingMember(keyName,desc,ttl);

			// Validate
			Assert.AreEqual(keyName,appKeyRingMember.KeyName,"A10: ");
			Assert.AreEqual(desc, appKeyRingMember.Description,"A20: ");
			Assert.AreEqual(ttl,appKeyRingMember.TTL,"A30: ");
			Assert.AreEqual(1,appKeyRingMember.CurrentVersion, "A40: ");
			Assert.AreEqual(EnumObjectEncryptionStatus.Active,appKeyRingMember.Status,"A50: ");

			// Version Count should be 1.
			Assert.AreEqual(1, appKeyRingMember.VersionCount(), "A100: ");


		}


		// Test Version Bump
		[Test]
		public void VersionBump_Success () {
			// Setup
			string keyName = "ab20";
			string desc = "some text";
			TimeUnit ttl = new TimeUnit("3d");

			// Test
			AppKeyRingMember appKeyRingMember = new AppKeyRingMember(keyName, desc, ttl);

			// Current Version should be 1.
			Assert.AreEqual(1, appKeyRingMember.CurrentVersion, "A10: ");
			EncryptionKeyVersioned firstEncryptionKeyVersioned = appKeyRingMember.GetEncryptionKeyVersioned();

			// Bump the version
			appKeyRingMember.BumpVersion();


			// Validate
			Assert.AreEqual(2, appKeyRingMember.CurrentVersion, "A110: ");
			EncryptionKeyVersioned secondEncryptionKeyVersioned = appKeyRingMember.GetEncryptionKeyVersioned();
			Assert.AreEqual(2,secondEncryptionKeyVersioned.Version,"A120: ");
			Assert.GreaterOrEqual(secondEncryptionKeyVersioned.CreatedAt,firstEncryptionKeyVersioned.CreatedAt,"A130: ");
			Assert.AreEqual(EnumEncryptionKeyStatus.Current,secondEncryptionKeyVersioned.Status,"A140: ");

			// The original Key's status should be set to previous.
			Assert.AreEqual(EnumEncryptionKeyStatus.Previous, firstEncryptionKeyVersioned.Status);


			// Make sure the Secrets are different.
			Assert.AreNotEqual(firstEncryptionKeyVersioned.Secret.ToArray(),secondEncryptionKeyVersioned.Secret.ToArray(),"A200:  Secrets were the same.  They must be different.");

			// Version Count should be 1.
			Assert.AreEqual(2, appKeyRingMember.VersionCount(), "A210: ");

		}
	}
}

using NUnit.Framework;
using SlugEnt;
using SlugEnt.EncryptionService;

namespace Test_EncryptionService {
	[TestFixture]
	public class Test_EncryptionServiceClass {

		[Test]
		public void InsertEncryptionObject () {
			// Setup
			string key = "ABC.XYZ.123";
			string desc = "testing Object";
			TimeUnit ttl = new TimeUnit("5d");


			EncryptionService encryptionService = new EncryptionService();
			AppKeyRingMember encB = new AppKeyRingMember(key, desc, ttl);
			AppKeyRingMember encA = new AppKeyRingMember(key + ".A",desc + ".A", ttl.AddDays(2));
			AppKeyRingMember encC = new AppKeyRingMember(key + ".C",desc + ".C", ttl.AddDays(5));

			encryptionService.InsertNew(encA);
			encryptionService.InsertNew(encB);
			encryptionService.InsertNew(encC);

			// Testing
			AppKeyRingMember enc = encryptionService.Get(encB.KeyName);


			// Validation
			Assert.AreEqual(encB.KeyName,enc.KeyName,"A10:");
			Assert.AreEqual(encB.TTL,enc.TTL,"A30:");
		}
	}
}
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
			EncryptionObject encB = new EncryptionObject(key, desc, ttl);
			EncryptionObject encA = new EncryptionObject(key + ".A",desc + ".A", ttl.AddDays(2));
			EncryptionObject encC = new EncryptionObject(key + ".C",desc + ".C", ttl.AddDays(5));

			encryptionService.Insert(encA);
			encryptionService.Insert(encB);
			encryptionService.Insert(encC);

			// Testing
			EncryptionObject enc = encryptionService.Get(encB.Id);


			// Validation
			Assert.AreEqual(encB.Id,enc.Id,"A10:");
			Assert.AreEqual(encB.KeyName,enc.KeyName,"A20:");
			Assert.AreEqual(encB.TTL,enc.TTL,"A30:");
		}
	}
}
using NUnit.Framework;
using SlugEnt;
using SlugEnt.EncryptionService;

namespace Test_EncryptionService
{
	[TestFixture]
	public class Test_EncryptionObject
	{
		[SetUp]
		public void Setup()
		{
		}

		[Test]
		public void Constructor() {
			string key = "ABC.XYZ.123";
			string desc = "testing Object";
			TimeUnit ttl = new TimeUnit("5d");

			EncryptionObject encryptionObject = new EncryptionObject(key,desc,ttl);

			Assert.AreEqual(key,encryptionObject.KeyName,"A10:");
			Assert.AreEqual(desc, encryptionObject.Description,"A20:");
			Assert.AreEqual(ttl,encryptionObject.TTL,"A30:");
			Assert.IsNotEmpty(encryptionObject.Id.ToString(),"A40:");
			Assert.AreEqual(0,encryptionObject.CurrentVersion,"A50:");
			Assert.AreEqual(EnumObjectEncryptionStatus.Active,encryptionObject.Status,"A60:");
		}



	}
}
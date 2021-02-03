using System;
using System.Collections.Generic;
using System.Text;

namespace Test_EncryptionService
{
	/// <summary>
	/// Used to test completely test if encryption process is working, This stores the data that was randomly choosen
	/// to be encrypted.  There will be many more Keyname/versions that were not selected...  We should be able
	/// to decrypt back to original message merely by passing the dataEncrypted member.
	/// </summary>
	public struct KeyRing_sample {
		public string keyName;
		public ushort version;
		public string dataOriginal;
		public byte [] dataEncrypted;
	}

}

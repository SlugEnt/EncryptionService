using System;

namespace SlugEnt.Encryption.Common
{
	public class EncryptionConstants 
	{
		// These must NOT Be changed - EVER. It may break existing encrypted objects.  Serious, as in significant testing should be performed if this is changed.
		public const int BIT_SIZE = 256;
		public const int BYTE_SIZE = 32;
		public const int IV_SIZE = 16;
		public const int KEYNAME_SIZE = 4;
	}
}

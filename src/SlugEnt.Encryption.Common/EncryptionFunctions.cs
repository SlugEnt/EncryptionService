using System;
using System.Collections.Generic;
using System.Text;

namespace SlugEnt.Encryption.Common
{
	public class EncryptionFunctions
	{
		/// <summary>
		///     Validates that the KeyName is of the correct size.  Throws an error if it is not.
		/// </summary>
		/// <param name="keyName">The value to validate</param>
		public static void ValidateKeyNameShort(string keyName)
		{
			if (keyName.Length != EncryptionConstants.KEYNAME_SIZE)
			{
				throw new ArgumentException("KeyNameShort length must be exactly [" + EncryptionConstants.KEYNAME_SIZE + "] characters long");
			}
		}
	}
}

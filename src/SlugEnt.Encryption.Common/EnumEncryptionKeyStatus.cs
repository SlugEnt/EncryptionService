using System;
using System.Collections.Generic;
using System.Text;

namespace SlugEnt.EncryptionService
{
	/// <summary>
	/// Statuses of the EncryptionKey
	/// </summary>
	public enum EnumEncryptionKeyStatus
	{
		/// <summary>
		/// This is the current encryption key 
		/// </summary>
		Current = 0,

		/// <summary>
		/// This is a previous encryption key version
		/// </summary>
		Previous = 10,

		/// <summary>
		/// This encryption key is Retired and should no longer be in any use.
		/// </summary>
		Retired = 255
	}
}

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
		Current = 0,
		Previous = 10,
		Retired = 255
	}
}

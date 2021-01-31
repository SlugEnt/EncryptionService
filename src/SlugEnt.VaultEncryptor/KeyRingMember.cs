using System;
using System.Collections.Generic;
using System.Text;
using SlugEnt.EncryptionService;

namespace SlugEnt.VaultEncryptor
{
	public class KeyRingMember
	{
		// Store the keys by their Version #
		private Dictionary<ushort, EncryptionKeyVersioned> _versionedKeys;

		/// <summary>
		/// Constructs a new KeyRing Member.  It is critical that the Constructor be passed what is the current EncryptionKeyVersioned object for a given KeyName.
		/// </summary>
		/// <param name="encryptionKeyVersioned">The CURRENT version of the KeyName</param>
		public KeyRingMember (EncryptionKeyVersioned encryptionKeyVersioned) {
			KeyName = encryptionKeyVersioned.KeyNameShort;
			_versionedKeys = new Dictionary<ushort, EncryptionKeyVersioned>();
			_versionedKeys.Add(encryptionKeyVersioned.Version,encryptionKeyVersioned);
			CurrentKey = encryptionKeyVersioned;
		}


		/// <summary>
		/// The KeyName
		/// </summary>
		public string KeyName { get; }


		/// <summary>
		/// The current version number of this Key Name
		/// </summary>
		public ushort CurrentVersionNumber { get; private set; }


		/// <summary>
		/// The Most current Encryption Key Versioned object for the given KeyName
		/// </summary>
		public EncryptionKeyVersioned CurrentKey { get; private set; }



		/// <summary>
		/// Retrieves the EncryptionKeyVersioned from the internal List.
		/// </summary>
		/// <param name="versionNumber"></param>
		/// <returns></returns>
		public EncryptionKeyVersioned GetVersion (ushort versionNumber) {
			EncryptionKeyVersioned foundKey;
			if ( !_versionedKeys.TryGetValue(versionNumber, out foundKey) ) {
				throw new ArgumentException("Unable to find EncryptionKeyVersioned object for KeyName [" + KeyName + "] with the version number: [" + versionNumber + "]");
			}

			return foundKey;

		}



		#region "Unit Test Only"
		/// <summary>
		/// For Unit Testing Only - Returns a dictionary item with the given version #
		/// </summary>
		/// <param name="version"></param>
		/// <returns></returns>
		internal EncryptionKeyVersioned UT_GetDictionaryItem (ushort version) {
			EncryptionKeyVersioned output;
			bool success = _versionedKeys.TryGetValue(version, out output);
			if ( !success ) return null;
			return output;
		}
		#endregion
	}
}

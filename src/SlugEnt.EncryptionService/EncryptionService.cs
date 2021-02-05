using System;
using System.Collections.Generic;

namespace SlugEnt.EncryptionService
{
	public class EncryptionService {
		private string MasterEncryptionKey = "abc45443gtrgegtr87056434TRTGTR434rgfgtPLAtg";

		private Dictionary<string, AppKeyRingMember> _keyRing;


		/// <summary>
		/// Returns the requested EncryptionObject if it exists or null if it does not.
		/// </summary>
		/// <param name="id"></param>
		/// <returns></returns>
		public AppKeyRingMember Get (string id) {
			AppKeyRingMember obj;
			if ( !_keyRing.TryGetValue(id, out obj) ) return null;
			return obj;
		}


		/// <summary>
		/// Inserts the given Encryption Object into the Objects dictionary.  Returns False if the keyName already exists.
		/// </summary>
		/// <param name="encryptionObject"></param>
		/// <returns></returns>
		public bool InsertNew (AppKeyRingMember encryptionObject) {
			if ( !_keyRing.TryAdd(encryptionObject.KeyName, encryptionObject) ) return false;

			return true;
		}


		/// <summary>
		/// Retrieves the requested KeyVersioned object.  If Version is 0 it retrieves the current key, otherwise the specific version is retrieved.  Returns null if the key cannot be found.
		/// </summary>
		/// <param name="keyName">KeyName to retrieve</param>
		/// <param name="version">The version to retreive.  Zero means current version</param>
		/// <returns></returns>
		public EncryptionKeyVersioned GetKeyVersioned (string keyName, ushort version) {
			// First - get the AppKeyRingMember
			AppKeyRingMember appKeyRingMember;
			if ( !_keyRing.TryGetValue(keyName, out appKeyRingMember) ) {
				return null;
			}

			// Now search for the specific version
			EncryptionKeyVersioned encryptionKeyVersioned = appKeyRingMember.GetEncryptionKeyVersioned(version);
			return encryptionKeyVersioned;
		}



		/// <summary>
		/// Scans thru all keys, creating new versions of any keys whose current version has expired.
		/// </summary>
		internal void KeyMaintenance () {

		}
	}
}

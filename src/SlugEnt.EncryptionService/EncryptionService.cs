using System;
using System.Collections.Generic;

namespace SlugEnt.EncryptionService
{
	public class EncryptionService {
		private string MasterEncryptionKey = "abc45443gtrgegtr87056434TRTGTR434rgfgtPLAtg";

		private Dictionary<string, EncryptionObject> _encryptionObjects;


		/// <summary>
		/// Returns the requested EncryptionObject if it exists or null if it does not.
		/// </summary>
		/// <param name="id"></param>
		/// <returns></returns>
		public EncryptionObject Get (string id) {
			EncryptionObject obj;
			if ( !_encryptionObjects.TryGetValue(id, out obj) ) return null;
			return obj;
		}


		/// <summary>
		/// Inserts the given Encryption Object into the Objects dictionary.
		/// </summary>
		/// <param name="encryptionObject"></param>
		/// <returns></returns>
		public bool Insert (EncryptionObject encryptionObject) {
			if ( !_encryptionObjects.TryAdd(encryptionObject.KeyID, encryptionObject) ) return false;
			return true;
		}



	}
}

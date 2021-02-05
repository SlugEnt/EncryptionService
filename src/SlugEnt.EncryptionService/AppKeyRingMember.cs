using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using SlugEnt.Encryption.Common;


namespace SlugEnt.EncryptionService
{
	/// <summary>
	/// An Application KeyRingMember that stores the encryption keys associated with a particular application/keyname.
	/// </summary>
	public class AppKeyRingMember {
		// The dictionary of versioned EncryptionKys.
		private Dictionary<ushort, EncryptionKeyVersioned> _encryptionKeyVersions;


		/// <summary>
		/// The identifier used to identify this key.
		/// </summary>
		public string KeyName { get; }


		/// <summary>
		/// Describes the purpose of the key
		/// </summary>
		public string Description;


		/// <summary>
		/// The lifetime of a specific version of the key
		/// </summary>
		public TimeUnit TTL { get; set; }


		/// <summary>
		/// Status of this key.
		/// </summary>
		public EnumObjectEncryptionStatus Status { get; set; }


		/// <summary>
		/// What the current - active - version of this key is.
		/// </summary>
		public ushort CurrentVersion { get; set; }


		/// <summary>
		/// The number of versions of this key.
		/// </summary>
		/// <returns></returns>
		public ushort VersionCount () {
			return (ushort) _encryptionKeyVersions.Count;
		}
		

		/// <summary>
		/// Creates a new EncryptionObject, sets status to Active.
		/// </summary>
		/// <param name="keyName">The unique KeyName</param>
		/// <param name="description">What this key is used for</param>
		/// <param name="ttl">Lifetime of the current key.</param>
		public AppKeyRingMember (string keyName, string description, TimeUnit ttl) {
			EncryptionFunctions.ValidateKeyNameShort(keyName);
			KeyName = keyName;
			
			Description = description;
			TTL = ttl;

			// Setup internal Dictionary to keep track of this KeyNames Versioned objects
			_encryptionKeyVersions = new Dictionary<ushort, EncryptionKeyVersioned>();


			// Create 1st Encryption Key Versioned Object and add to the Versioned Dictionary.
			EncryptionKeyVersioned encryptionKeyVersioned = new EncryptionKeyVersioned(keyName,ttl);
			_encryptionKeyVersions.Add(encryptionKeyVersioned.Version,encryptionKeyVersioned);

			CurrentVersion = encryptionKeyVersioned.Version;
			Status = EnumObjectEncryptionStatus.Active;

		}


		/// <summary>
		/// Returns the EncryptedKeyVersioned object for the version specified.  Returns null if the requested version does not exist.
		/// </summary>
		/// <param name="versionNumber">The version to retrieve.  0 means retrieve the current version</param>
		/// <returns></returns>
		public EncryptionKeyVersioned GetEncryptionKeyVersioned (ushort versionNumber = 0) {
			if ( versionNumber == 0 ) versionNumber = CurrentVersion;

			EncryptionKeyVersioned encryptionKeyVersioned;
			if ( !_encryptionKeyVersions.TryGetValue(versionNumber, out encryptionKeyVersioned) ) {
				return null;
				//throw new ArgumentException("The version [" + versionNumber + "] was not found for Key [" + KeyName + "]");
			}

			return encryptionKeyVersioned;
		}



		/// <summary>
		/// Creates a new EncryptionKeyVersioned object that is 1 version newer than the current.  The Current is then set to the new EncryptionKeyVersioned object.
		/// </summary>
		public void BumpVersion () {
			EncryptionKeyVersioned encryptionKeyVersioned = GetEncryptionKeyVersioned();
			encryptionKeyVersioned.Status = EnumEncryptionKeyStatus.Previous;
			EncryptionKeyVersioned nextVersion = encryptionKeyVersioned.NewVersion();
			CurrentVersion = nextVersion.Version;

			_encryptionKeyVersions.Add(nextVersion.Version, nextVersion);
		}

	}
}

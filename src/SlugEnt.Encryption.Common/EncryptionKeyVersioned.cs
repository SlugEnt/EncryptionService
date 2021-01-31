using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SlugEnt.Encryption.Common;

[assembly: InternalsVisibleTo("Test_EncryptionService")]


namespace SlugEnt.EncryptionService {
	/// <summary>
	///     A Versioned Encryption Key wrapper.  This is the object that contains a specific secret that is used to encrypt /
	///     decrypt a given piece of data.
	/// </summary>
	public class EncryptionKeyVersioned : IEquatable<EncryptionKeyVersioned> {
		// These can never change after construction.

		private Memory<byte> _secret;


		/// <summary>
		///     Creates a new Encryption Key Versioned Object - This constructor is for creating a truly new EncryptionKeyVersioned
		///     object. If you are loading from JSON or other, ensure you are using one
		///     of the methods that creates an EncryptionKeyVersioned object.
		/// </summary>
		/// <param name="applicationId"></param>
		/// <param name="ttl"></param>
		/// <param name="secret">
		///     It is highly recommended to let the app generate a secret for you.  If you provide it must be
		///     exactly of the correct size.
		/// </param>
		public EncryptionKeyVersioned (Guid applicationId, string keyNameShortShort, TimeUnit ttl, string secret = "") {
			ApplicationId = applicationId;

			ValidateKeyNameShort(keyNameShortShort);
			KeyNameShort = keyNameShortShort;
			Version = 1;
			Id = BuildID(KeyNameShort, Version, true);

			CreatedAt = DateTime.Now;
			LastRequestedAt = CreatedAt;

			TTL = ttl;


			// Create the secret.
			if (secret != "")
			{
				//				if (secret.Length != EncryptionConstants.BYTE_SIZE) throw new ArgumentException("Invalid Secret Size.  Must be: " + EncryptionConstants.BYTE_SIZE);
				SetSecret(secret);
			}
			else
			{
				// Generate truly random bytes.
				RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
				byte[] randomBytes = new byte[EncryptionConstants.BYTE_SIZE];
				rngCryptoServiceProvider.GetBytes(randomBytes);
				SetSecret(randomBytes);
			}
		}


		/// <summary>
		/// Internal constructor that allows the Version to be incremented by 1 or 
		/// </summary>
		/// <param name="applicationId"></param>
		/// <param name="keyNameShortShort"></param>
		/// <param name="ttl"></param>
		/// <param name="version"></param>
		internal EncryptionKeyVersioned (Guid applicationId, string keyNameShortShort, TimeUnit ttl, ushort version) : this(applicationId,keyNameShortShort,ttl) {
			Version = version;
		}


		/// <summary>
		///     The Application this Versioned Encryption Key is for.
		/// </summary>
		public Guid ApplicationId { get; }


		/// <summary>
		///     Date this versioned Encryption Key was created at.
		/// </summary>
		public DateTime CreatedAt { get; }



		/// <summary>
		///     Unique ID
		/// </summary>
		public string Id { get; }


		/// <summary>
		///     This is the short name for the key.
		/// </summary>
		public string KeyNameShort { get; }


		/// <summary>
		///     The last time this key was requested
		/// </summary>
		public DateTime LastRequestedAt { get; }


		/// <summary>
		///     The secret used to encrypt and decrypt data
		/// </summary>
		public ReadOnlySpan<byte> Secret {
			get {
				Span<byte> value = _secret.Span;
				return value;
			}
		}


		/// <summary>
		///     The status of this Encryption Key
		/// </summary>
		public EnumEncryptionKeyStatus Status { get; private set; }


		/// <summary>
		///     The lifetime of this versioned Encryption Key.  Lifetime calculated from createdAt
		/// </summary>
		public TimeUnit TTL { get; }



		/// <summary>
		///     The version number of this EncryptionKey
		/// </summary>
		public ushort Version { get; }


		/// <summary>
		///     The ID is the Short Key Name with the version number appended to end of it.
		/// </summary>
		/// <param name="shortKeyName">The Short Key Name.  Must be a valid short Key Name</param>
		/// <param name="version">The version number</param>
		/// <returns>The ID that results from the Short Key Name and the Version Number</returns>
		public static string BuildID (string shortKeyName, ushort version, bool skipValidation = false) {
			if ( !skipValidation ) { ValidateKeyNameShort(shortKeyName); }

			return shortKeyName + version;
		}


		/// <summary>
		///     The hashcode is the KeyName plus the version number.
		/// </summary>
		/// <returns></returns>
		public override int GetHashCode () {
			return HashCode.Combine(KeyNameShort, Version);
		}



		/// <summary>
		///     Saves the secret into the Secret Parameter
		/// </summary>
		/// <param name="secret"></param>
		internal void SetSecret (string secret) {
			if ( secret.Length != EncryptionConstants.BYTE_SIZE ) {
				throw new ArgumentException("Secret must be exactly [" + EncryptionConstants.BYTE_SIZE + "] bytes in size.");
			}

			_secret = Encoding.ASCII.GetBytes(secret);
		}


		/// <summary>
		///     Saves the secret into the Secret Parameter
		/// </summary>
		/// <param name="secret"></param>
		internal void SetSecret (byte [] secret) {
			if ( secret.Length != EncryptionConstants.BYTE_SIZE ) {
				throw new ArgumentException("Secret must be exactly [" + EncryptionConstants.BYTE_SIZE + "] bytes in size.");
			}

			_secret = secret;
		}



		/// <summary>
		/// Creates a new EncryptedKeyVersion Object based upon the current object, but with an Updated Version Number
		/// </summary>
		/// <param name="updatedVersionNumber">Version # for the new object.  Set to zero (default) to auto increment the current version by 1.</param>
		/// <returns></returns>
		public EncryptionKeyVersioned NewVersion (ushort updatedVersionNumber = 0) {
			ushort version;
			if ( updatedVersionNumber == 0 )
				version = (ushort) (Version + 1);
			else
				version = updatedVersionNumber;

			EncryptionKeyVersioned b = new EncryptionKeyVersioned(this.ApplicationId,this.KeyNameShort,this.TTL,version);
			return b;
		}



		/// <summary>
		///     Validates that the KeyName is of the correct size.  Throws an error if it is not.
		/// </summary>
		/// <param name="keyName">The value to validate</param>
		internal static void ValidateKeyNameShort (string keyName) {
			if ( keyName.Length != EncryptionConstants.KEYNAME_SIZE ) {
				throw new ArgumentException("KeyNameShort length must be exactly [" + EncryptionConstants.KEYNAME_SIZE + "] characters long");
			}
		}

		public bool Equals([AllowNull] EncryptionKeyVersioned other) {
			if ( (this.KeyNameShort == other.KeyNameShort) && (this.ApplicationId == other.ApplicationId) && (this.Version == other.Version) ) return true;
			return false;
		}


		public static bool operator == (EncryptionKeyVersioned x, EncryptionKeyVersioned y) {
			return ((x.KeyNameShort == y.KeyNameShort) && (x.ApplicationId == y.ApplicationId) && (x.Version == y.Version));
		}


		public static bool operator != (EncryptionKeyVersioned x, EncryptionKeyVersioned y) {
			return !((x.KeyNameShort == y.KeyNameShort) && (x.ApplicationId == y.ApplicationId) && (x.Version == y.Version));
		}
		
	}
}
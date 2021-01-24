using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;


[assembly: InternalsVisibleTo("Test_EncryptionService")]


namespace SlugEnt.VaultEncryptor
{

	internal class EncryptorInfo {
		internal const short STORAGE_LEN = 16;
		internal const short RECORD_IDENTIFIER_START = 0;
		internal const short RECORD_IDENTIFIER_LEN = 2;
		internal const short KEYNAME_START = RECORD_IDENTIFIER_LEN;
		internal const short KEYNAME_LENGTH = 4;
		internal const short VER_START = KEYNAME_START + KEYNAME_LENGTH;
		internal const short VER_LENGTH = 2;
		internal const short TIME_START = VER_START + VER_LENGTH;
		internal const short TIME_LENGTH = 8;

		internal const ushort RECORD_IDENTIFIER_VALUE = 43275;		// The Record identifier as an unsigned short

		internal byte [] _storage;
		

		/// <summary>
		/// Constructs an EncryptorInfo object from an existing data stream.
		/// </summary>
		/// <param name="existingObject"></param>
		internal EncryptorInfo (byte[] existingObject) {
			// Copy the passed in buffer to _storage
			_storage = new byte[STORAGE_LEN];
			Buffer.BlockCopy(existingObject,0,_storage,0,STORAGE_LEN);
			
			// Ensure it is an EncryptorInfo object
			if ( RecordIdentifier == RECORD_IDENTIFIER_VALUE ) IsEncryptorInfo = true;
			else throw new ArgumentException("existingObject is not an EncryptorInfo data object.");
		}



		/// <summary>
		/// Constructor to be used when one wants to create a new EncryptorInfo data object
		/// </summary>
		internal EncryptorInfo () {
			_storage = new byte[STORAGE_LEN];

			// Set RecordIdentifier.
			SetRecordIdentifier();
			IsEncryptorInfo = true;
		}



		/// <summary>
		/// Returns true if the current data is a EncryptorInfo object.  Only necessary to read when creating a EncryptorInfo object from an existing data stream.
		/// </summary>
		public bool IsEncryptorInfo {
			get;
			private set;
		}



		/// <summary>
		/// The Record Identifier used to confirm that this might be a EncryptorInfo object
		/// </summary>
		internal ushort RecordIdentifier {
			get {
				ushort[] shortened = new ushort[1];
				Buffer.BlockCopy(_storage, RECORD_IDENTIFIER_START, shortened, 0, 2);
				return shortened[0];
			}
		}



		/// <summary>
		/// Sets the value of the record identifier
		/// </summary>
		private void SetRecordIdentifier () {
			_storage[RECORD_IDENTIFIER_START] = 0xB;
			_storage[RECORD_IDENTIFIER_START + 1] = 0xA9;
		}



		/// <summary>
		/// The KeyName is the unique 4 character identifier that tells the system what Key was used to encrypt this data.
		/// </summary>
		internal string KeyName {
			get {
				return Encoding.ASCII.GetString(_storage, KEYNAME_START, KEYNAME_LENGTH);
			}
			set {
				if (value == null) throw new ArgumentException("KeyName cannot be null");
				if (value.Length != EncryptorInfo.KEYNAME_LENGTH) throw new ArgumentException("KeyName must be exactly 4 characters");

				System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
				encoding.GetBytes(value, 0, 4, _storage, KEYNAME_START);
			}
		}


		/// <summary>
		/// The version of the KeyName that this data was encrypted with.
		/// </summary>
		internal ushort Version {
			get {
				ushort[] shortened = new ushort[1];
				Buffer.BlockCopy(_storage,VER_START,shortened,0,2);
				return shortened [0];

				// Alternative means, but supposedly above is faster.  Have not tested myself.
				// return BitConverter.ToUInt16(_storage, VER_START);
			}
			set {
				byte [] shortened = BitConverter.GetBytes(value);
				Buffer.BlockCopy(shortened,0,_storage,VER_START,2);
			}
		}


		internal DateTime LastUpdated {
			get {
				//DateTime[] time = new DateTime[1];
				DateTime dateTime = DateTime.FromBinary(BitConverter.ToInt64(_storage, TIME_START));
				//Buffer.BlockCopy(_storage, TIME_START, time, 0, 8);
				return dateTime;
			}

			set {
				byte[] time = BitConverter.GetBytes(value.Ticks);
				Buffer.BlockCopy(time, 0, _storage, TIME_START,8);
			}
		}



		/// <summary>
		/// Returns the EncryptorInfo object as an array of bytes (Array is copied)
		/// </summary>
		/// <returns></returns>
		public byte [] GetAsBytes () {
			byte[] returnBytes = new byte[STORAGE_LEN];
			Buffer.BlockCopy(_storage,0,returnBytes,0,STORAGE_LEN);
			return returnBytes;
		}


		/// <summary>
		/// Returns a pointer to the underlying byte array.  This is for speed during saving of this to some permanent data store.
		/// </summary>
		/// <returns></returns>
		public byte [] GetBytes () {
			return _storage;
		}
	}
}

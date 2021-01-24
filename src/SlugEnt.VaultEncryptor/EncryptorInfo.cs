using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;


[assembly: InternalsVisibleTo("Test_EncryptionService")]


namespace SlugEnt.VaultEncryptor
{
	internal class EncryptorInfo {
		internal const short STORAGE_LEN = 16;
		internal const short KEYNAME_START = 0;
		internal const short KEYNAME_LENGTH = 4;
		internal const short VER_START = 4;
		internal const short VER_LENGTH = 2;
		internal const short TIME_START = 6;
		internal const short TIME_LENGTH = 8;

		internal byte [] _storage;

		
		internal EncryptorInfo () {
			_storage = new byte[16];
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
	}
}

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SlugEnt.EncryptionService
{
	public class EncryptionObject {
		public Guid Id;
		public string KeyName;
		public string Description;
		public TimeUnit TTL;
		public EnumObjectEncryptionStatus Status;
		public int CurrentVersion;


		/// <summary>
		/// Creates a new EncryptionObject, sets status to Active.
		/// </summary>
		/// <param name="keyName"></param>
		/// <param name="description"></param>
		/// <param name="ttl"></param>
		public EncryptionObject (string keyName, string description, TimeUnit ttl) {
			KeyName = keyName;
			Description = description;
			TTL = ttl;
			CurrentVersion = 0;
			Id = new Guid();
			Status = EnumObjectEncryptionStatus.Active;
		}



	}
}

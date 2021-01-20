using System;
using System.Collections.Generic;
using System.Text;

namespace SlugEnt.EncryptionService
{
	class EncryptionKeyVersioned {
		public Guid Id { get; private set; }
		public Guid AppEncryptionKeyId { get; private set; }
		public int Version { get; private set; }
		public string Secret { get; private set; }
		public EnumEncryptionKeyStatus Status { get; private set; }
		public DateTime CreatedAt { get; private set; }
		public DateTime LastRequestedAt { get; private set; }
		public TimeUnit TTL { get; private set; }
	}
}

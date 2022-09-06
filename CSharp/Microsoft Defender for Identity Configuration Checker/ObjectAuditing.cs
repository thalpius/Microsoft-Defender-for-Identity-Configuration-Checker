using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    public class ObjectAuditing
    {
        public class ObjectAudit
        {
            public String GetObjectType { get; set; }
            public Boolean Set { get; set; }
        }

        public static List<ObjectAudit> CheckObjectAuditing()
        {
            List<ObjectAudit> ObjectAuditing = new List<ObjectAudit> {
                new ObjectAudit
                {
                    GetObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2",
                    Set = false
                },
                new ObjectAudit
                {
                    GetObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2",
                    Set = false
                },
                new ObjectAudit
                {
                    GetObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2",
                    Set = false
                }
            };

            for (int index = 0; index < ObjectAuditing.Count; index++)
            {
                try
                {
                    DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
                    Object distinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;

                    using (DirectoryEntry de = new DirectoryEntry(@"LDAP://" + distinguishedName))
                    {
                        de.Options.SecurityMasks = SecurityMasks.Sacl;
                        de.RefreshCache();
                        ActiveDirectorySecurity Sec = de.ObjectSecurity;
                        foreach (ActiveDirectoryAuditRule ar in Sec.GetAuditRules(true, true, typeof(NTAccount)))
                        {
                            string GetIdentity = ar.IdentityReference.ToString();
                            if (GetIdentity == "Everyone")
                            {
                                string GetAuditAccess = ar.ActiveDirectoryRights.ToString();
                                if (GetAuditAccess.Contains("CreateChild") && GetAuditAccess.Contains("DeleteChild") && GetAuditAccess.Contains("Self") && GetAuditAccess.Contains("WriteProperty") && GetAuditAccess.Contains("DeleteTree") && GetAuditAccess.Contains("ExtendedRight") && GetAuditAccess.Contains("Delete") && GetAuditAccess.Contains("WriteDacl") && GetAuditAccess.Contains("WriteOwner"))
                                {
                                    string GetObjectType = ar.InheritedObjectType.ToString();
                                    if (GetObjectType.Equals(ObjectAuditing[index].GetObjectType))
                                    {
                                        ObjectAuditing[index].Set = true;
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                    ObjectAuditing[index].Set = false;
                }
            }
            return ObjectAuditing;
        }
    }
}

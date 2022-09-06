using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Windows.Forms;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    internal class ADFSAuditing
    {
        public static string GetRootDistinguishedName()
        {
            DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
            Object distinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;
            return distinguishedName.ToString();
        }
        public static bool CheckADFSAuditing()
        {
            bool CheckAuditing = false;
            bool CheckAuditingADFS = false;
            try
            {
                string distinguishedName = GetRootDistinguishedName();
                using (DirectoryEntry de = new DirectoryEntry(@"LDAP://CN=ADFS,CN=Microsoft,CN=Program Data," + distinguishedName))
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
                            if (GetAuditAccess.Contains("ReadProperty") && GetAuditAccess.Contains("WriteProperty"))
                            {
                                string GetInheritanceType = ar.InheritanceType.ToString();
                                if (GetInheritanceType.Equals("All"))
                                {
                                    string GetObjectType = ar.InheritedObjectType.ToString();
                                    if (GetObjectType.Equals("00000000-0000-0000-0000-000000000000"))
                                    {
                                        CheckAuditingADFS = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                CheckAuditing = false;
            }
            if ((CheckAuditingADFS == true))
            {
                CheckAuditing = true;
            }
            return CheckAuditing;
        }
    }
}

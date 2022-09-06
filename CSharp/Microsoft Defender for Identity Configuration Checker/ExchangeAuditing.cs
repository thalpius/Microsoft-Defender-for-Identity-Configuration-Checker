using System;
using System.DirectoryServices;
using System.Security.Principal;


namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    internal class ExchangeAuditing
    {
        public static string GetRootDistinguishedName()
        {
            DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
            Object distinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;
            return distinguishedName.ToString();
        }

        public static bool CheckExchangeAuditing()
        {
            bool CheckAuditing = false;
            bool CheckAuditingExchange = false;

            string distinguishedName = GetRootDistinguishedName();
            using (DirectoryEntry de = new DirectoryEntry(@"LDAP://CN=Configuration," + distinguishedName))
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
                        if (GetAuditAccess.Contains("WriteProperty"))
                        {
                            string GetInheritanceType = ar.InheritanceType.ToString();
                            if (GetInheritanceType.Equals("All"))
                            {
                                string GetObjectType = ar.InheritedObjectType.ToString();
                                if (GetObjectType.Equals("00000000-0000-0000-0000-000000000000"))
                                {
                                    CheckAuditingExchange = true;
                                }
                            }

                        }
                    }
                }
            }
            if ((CheckAuditingExchange == true))
            {
                CheckAuditing = true;
            }
            return CheckAuditing;
        }
    }
}

using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    internal class LDAPAuditing
    {
        public class RegKey
        {
            public String Key { get; set; }
            public String Subkey { get; set; }
            public int Value { get; set; }
            public Boolean Set { get; set; }
        }
        public static List<RegKey> CheckLDAPAuditing()
        {
            List<RegKey> RegkeysLDAPAuditing = new List<RegKey> {
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics",
                    Subkey = "15 Field Engineering",
                    Value = 0,
                    Set = false
                },
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                    Subkey = "Expensive Search Results Threshold",
                    Set = false
                },
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                    Subkey = "Inefficient Search Results Threshold",
                    Set = false
                },
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                    Subkey = "Search Time Threshold (msecs)",
                    Set = false
                }
            };

            using (RegistryKey keyDiagnostics = Registry.LocalMachine.OpenSubKey(RegkeysLDAPAuditing[0].Key, false))
            {
                Object CheckNTLMAuditing = keyDiagnostics.GetValue(RegkeysLDAPAuditing[0].Subkey);
                if (CheckNTLMAuditing != null)
                {
                    if (Int32.Parse(CheckNTLMAuditing.ToString()) == RegkeysLDAPAuditing[0].Value)
                    {
                        RegkeysLDAPAuditing[0].Set = true;
                    }
                }
            }

            for (int index = 1; index < RegkeysLDAPAuditing.Count; index++)
            {
                using (RegistryKey keyDiagnostics = Registry.LocalMachine.OpenSubKey(RegkeysLDAPAuditing[index].Key, false))
                {
                    Object CheckNTLMAuditing = keyDiagnostics.GetValue(RegkeysLDAPAuditing[index].Subkey);
                    if (CheckNTLMAuditing == null)
                    {
                        RegkeysLDAPAuditing[index].Set = true;
                    }
                }
            }
            return RegkeysLDAPAuditing;
        }
    }
}

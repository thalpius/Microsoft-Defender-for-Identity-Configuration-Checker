using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    internal class NTLMAuditing
    {
        public class RegKey
        {
            public String Key { get; set; }
            public String Subkey { get; set; }
            public int Value { get; set; }
            public Boolean Set { get; set; }
        }
        public static List<RegKey> CheckNTLMAuditing()
        {
            List<RegKey> RegkeysNTLMAuditing = new List<RegKey> {
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                    Subkey = "auditntlmindomain",
                    Value = 7,
                    Set = false
                },
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    Subkey = "restrictsendingntlmtraffic",
                    Value = 1,
                    Set = false
                },
                new RegKey
                {
                    Key = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                    Subkey = "auditreceivingntlmtraffic",
                    Value = 2,
                    Set = false
                },
            };

            for (int index = 0; index < RegkeysNTLMAuditing.Count; index++)
            {
                using (RegistryKey keyDiagnostics = Registry.LocalMachine.OpenSubKey(RegkeysNTLMAuditing[index].Key, false))
                {
                    Object CheckNTLMAuditing = keyDiagnostics.GetValue(RegkeysNTLMAuditing[index].Subkey);
                    if (CheckNTLMAuditing != null)
                    {
                        if (Int32.Parse(CheckNTLMAuditing.ToString()) == RegkeysNTLMAuditing[index].Value)
                        {
                            RegkeysNTLMAuditing[index].Set = true;
                        }
                    }
                }
            }
            return RegkeysNTLMAuditing;
        }
    }
}

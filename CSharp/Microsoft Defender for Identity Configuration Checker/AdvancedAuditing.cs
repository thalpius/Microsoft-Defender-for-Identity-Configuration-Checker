using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static Microsoft_Defender_for_Identity_Configuration_Checker.AdvancedAuditing;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    internal class AdvancedAuditing
    {
        public class Policy
        {
            public Guid Guid { get; set; }
            public int Value { get; set; }
            public Boolean Set { get; set; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public UInt32 AuditingInformation;
            public Guid AuditCategoryGuid;
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AuditQuerySystemPolicy(Guid pSubCategoryGuids, uint PolicyCount, out IntPtr ppAuditPolicy);

        public static List<Policy> CheckAdvancedAuditing()
        {
            List<Policy> PoliciesAdvancedAuditing = new List<Policy> {
                new Policy
                {
                    Guid = Guid.Parse("0cce923f-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce9238-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce9236-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce9237-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce9235-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce923b-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce9211-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                },
                new Policy
                {
                    Guid = Guid.Parse("0cce923c-69ae-11d9-bed3-505054503030"),
                    Value = 3,
                    Set = false
                }
            };

            AUDIT_POLICY_INFORMATION auditPolicyInformation = new AUDIT_POLICY_INFORMATION();
            int size = Marshal.SizeOf(auditPolicyInformation);

            for (int index = 0; index < PoliciesAdvancedAuditing.Count; index++)
            {
                IntPtr ptr = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(auditPolicyInformation, ptr, false);
                AuditQuerySystemPolicy(PoliciesAdvancedAuditing[index].Guid, 1, out ptr);
                auditPolicyInformation = (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(ptr, typeof(AUDIT_POLICY_INFORMATION));
                Marshal.FreeHGlobal(ptr);

                if (auditPolicyInformation.AuditingInformation == PoliciesAdvancedAuditing[index].Value)
                {
                    PoliciesAdvancedAuditing[index].Set = true;
                }
            }
            return PoliciesAdvancedAuditing;
        }
    }
}

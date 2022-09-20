using System;
using System.Collections.Generic;
using System.Management;
using System.Security.Principal;
using System.Windows.Forms;
using static Microsoft_Defender_for_Identity_Configuration_Checker.NTLMAuditing;
using static Microsoft_Defender_for_Identity_Configuration_Checker.LDAPAuditing;
using static Microsoft_Defender_for_Identity_Configuration_Checker.AdvancedAuditing;
using static Microsoft_Defender_for_Identity_Configuration_Checker.ObjectAuditing;

namespace Microsoft_Defender_for_Identity_Configuration_Checker
{
    public partial class FormDashboard : Form
    {
        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern bool ReleaseCapture();
        public FormDashboard()
        {
            InitializeComponent();

            MoveSidePanel(BtnDashboard);

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;

            BtnAdvancedAuditing.Enabled = false;
            BtnADFSAuditing.Enabled = false;
            BtnNTLMAuditing.Enabled = false;
            BtnLDAPAuditing.Enabled = false;
            BtnObjectAuditing.Enabled = false;
            BtnADFSAuditing.Enabled = false;
            BtnExchangeAuditing.Enabled = false;

            richTextBoxLogging.AppendText("Welcome at my Microsoft Defender for Identity Configuration Checker!\n\n");
            richTextBoxLogging.AppendText("Website: https://thalpius.com\n");
            richTextBoxLogging.AppendText("GitHub: https://github.com/thalpius\n\n");

            if (CheckDomainController())
            {
                richTextBoxLogging.AppendText("Info: Looks like this server is a Domain Controller...\n");
            }
            else
            {
                richTextBoxLogging.AppendText("Warning: Please run this application as on a Domain Controller!\n");
            }
            if (CheckIsAdmin())
            {
                richTextBoxLogging.AppendText("Info: Looks like you are running the application as Administrator...\n");
            }
            else
            {
                richTextBoxLogging.AppendText("Warning: Please run this application as Administrator!\n");
            }
            if (CheckDomainController() & CheckIsAdmin())
            {
                BtnAdvancedAuditing.Enabled = true;
                BtnADFSAuditing.Enabled = true;
                BtnNTLMAuditing.Enabled = true;
                BtnLDAPAuditing.Enabled = true;
                BtnObjectAuditing.Enabled = true;
                BtnADFSAuditing.Enabled = true;
                BtnExchangeAuditing.Enabled = true;

                RefreshAdvancedAuditing();
                RefreshNTLMAuditing();
                RefreshLDAPAuditing();
                RefreshObjectAuditing();
                RefreshADFSAuditing();
                RefreshExchangeAuditing();
            }
        }

        public bool CheckDomainController()
        {
            bool domainController = false;
            try
            {
                ManagementScope wmiScope = new ManagementScope("\\\\localhost\\root\\cimv2");
                wmiScope.Connect();
                ManagementObjectSearcher moSearcher = new ManagementObjectSearcher(wmiScope, new ObjectQuery("SELECT DomainRole FROM Win32_ComputerSystem"));
                foreach (ManagementObject shareData in moSearcher.Get())
                {
                    int domainRole = int.Parse(shareData["DomainRole"].ToString());
                    if (domainRole >= 4)
                    {
                        domainController = true;
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                richTextBoxLogging.AppendText(ex.ToString());
                
            }
            return domainController;
        }

        public bool CheckIsAdmin()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            return isElevated;
        }

        private void MoveSidePanel(Control c)
        {
            SidePanel.Height = c.Height;
            SidePanel.Top = c.Top;
        }

        private void BtnDashboard_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnDashboard);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Dashboard_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = true;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnAdvancedAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnAdvancedAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Advanced_Auditing_512px;

            pnlAdvancedAuditing.Visible = true;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnNTLMAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnNTLMAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.NTLM_Auditing_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = true;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnLDAPAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnLDAPAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.LDAP_Auditing_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = true;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnObjectAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnObjectAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Object_Auditing_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = true;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnADFSAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnADFSAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.AD_FS_Auditing_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = true;
            pnlExchangeAuditing.Visible = false;
        }

        private void BtnExchangeAuditing_Click(object sender, EventArgs e)
        {
            MoveSidePanel(BtnExchangeAuditing);
            pbTitle.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Exchange_Auditing_512px;

            pnlAdvancedAuditing.Visible = false;
            pnlLDAPAuditing.Visible = false;
            pnlDashboard.Visible = false;
            pnlNTLMAuditing.Visible = false;
            pnlObjectAuditing.Visible = false;
            pnlADFSAuditing.Visible = false;
            pnlExchangeAuditing.Visible = true;
        }
        private void BtnExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void BtnLDAPAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "LDAP Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void BtnAdvancedAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "      Advanced Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void BtnNTLMAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "NTLM Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void BtnObjectAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "Object Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void BtnADFSAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "AD FS Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void BtnExchangeAuditing_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "      Exchange Auditing", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void btnRefreshLDAPAuditing_Click(object sender, EventArgs e)
        {
            RefreshLDAPAuditing();
        }

        private void btnRefreshAdvancedAuditing_Click(object sender, EventArgs e)
        {
            RefreshAdvancedAuditing();
        }

        private void btnRefreshNTLMAuditing_Click(object sender, EventArgs e)
        {
            RefreshNTLMAuditing();
        }

        private void btnRefreshObjectAuditing_Click(object sender, EventArgs e)
        {
            RefreshObjectAuditing();
        }

        private void btnRefreshADFSAuditing_Click(object sender, EventArgs e)
        {
            RefreshADFSAuditing();
        }

        private void pnlTop_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }

        private void RefreshAdvancedAuditing()
        {
            List<AdvancedAuditing.Policy> PolicyAdvancedAuditing = CheckAdvancedAuditing();
            if (PolicyAdvancedAuditing[0].Set == true && PolicyAdvancedAuditing[1].Set == true && PolicyAdvancedAuditing[2].Set == true && PolicyAdvancedAuditing[3].Set == true && PolicyAdvancedAuditing[4].Set == true && PolicyAdvancedAuditing[5].Set == true && PolicyAdvancedAuditing[6].Set == true)
            {
                picBoxAdvancedAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.LDAP_Auditing_512px;
            }
            else
            {
                picBoxAdvancedAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.LDAP_Auditing_512px_Greyscale;
            }
            if (PolicyAdvancedAuditing[0].Set == true)
            {
                pbAuditCredentialValidation.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditCredentialValidation.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[1].Set == true)
            {
                pbAuditComputerAccountManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditComputerAccountManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[2].Set == true)
            {
                pbAuditDistributionGroupManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditDistributionGroupManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[3].Set == true)
            {
                pbAuditSecurityGroupManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditSecurityGroupManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[4].Set == true)
            {
                pbAuditUserAccountManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditUserAccountManagement.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[5].Set == true)
            {
                pbAuditDirectoryServiceAccess.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditDirectoryServiceAccess.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (PolicyAdvancedAuditing[6].Set == true)
            {
                pbAuditSecuritySystemExtension.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditSecuritySystemExtension.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }

        public void RefreshNTLMAuditing()
        {
            List<NTLMAuditing.RegKey> RegkeysNTLMAuditing = CheckNTLMAuditing();
            if (RegkeysNTLMAuditing[0].Set == true && RegkeysNTLMAuditing[1].Set == true && RegkeysNTLMAuditing[2].Set == true)
            {
                picBoxNTLMAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.NTLM_Auditing_512px;
            }
            else
            {
                picBoxNTLMAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.NTLM_Auditing_512px_Greyscale;
            }
            if (RegkeysNTLMAuditing[0].Set == true)
            {
                pbOutgoingNTLMTrafficToRemoteServers.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbOutgoingNTLMTrafficToRemoteServers.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (RegkeysNTLMAuditing[1].Set == true)
            {
                pbAuditNTLMAuthenticationInThisDomain.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditNTLMAuthenticationInThisDomain.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (RegkeysNTLMAuditing[2].Set == true)
            {
                pbAuditIncomingNTLMTraffic.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbAuditIncomingNTLMTraffic.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }
        public void RefreshLDAPAuditing()
        {
            List<LDAPAuditing.RegKey> RegkeysLDAPAuditing = CheckLDAPAuditing();
            if (RegkeysLDAPAuditing[0].Set == true && RegkeysLDAPAuditing[1].Set == true && RegkeysLDAPAuditing[2].Set == true && RegkeysLDAPAuditing[3].Set == true)
            {
                picBoxLDAPAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.LDAP_Auditing_512px;
            }
            else
            {
                picBoxLDAPAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.LDAP_Auditing_512px_Greyscale;
            }
            if (RegkeysLDAPAuditing[0].Set == true)
            {
                pb15FieldEngineering.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pb15FieldEngineering.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (RegkeysLDAPAuditing[1].Set == true)
            {
                pbExpensiveSearchResultsThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbExpensiveSearchResultsThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (RegkeysLDAPAuditing[2].Set == true)
            {
                pbInefficientSearchResultsThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbInefficientSearchResultsThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (RegkeysLDAPAuditing[3].Set == true)
            {
                pbSearchTimeThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbSearchTimeThreshold.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }

        public void RefreshObjectAuditing()
        {
            List<ObjectAuditing.ObjectAudit> ObjectAuditing = CheckObjectAuditing();
            if (ObjectAuditing[0].Set == true && ObjectAuditing[1].Set == true && ObjectAuditing[2].Set == true && ObjectAuditing[3].Set == true && ObjectAuditing[4].Set == true)
            {
                picBoxObjectAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Object_Auditing_512px;
            }
            else
            {
                picBoxObjectAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Object_Auditing_512px_Greyscale;
            }
            if (ObjectAuditing[0].Set == true)
            {
                pbDescendantUserObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbDescendantUserObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (ObjectAuditing[1].Set == true)
            {
                pbDescendantGroupObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbDescendantGroupObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (ObjectAuditing[2].Set == true)
            {
                pbDescendantComputerObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbDescendantComputerObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (ObjectAuditing[3].Set == true)
            {
                pbDescendantGroupManagedServiceAccountObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbDescendantGroupManagedServiceAccountObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
            if (ObjectAuditing[4].Set == true)
            {
                pbDescendantManagedServiceAccountObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                pbDescendantManagedServiceAccountObjects.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }

        public void RefreshADFSAuditing()
        {
            bool adfsAuditing = ADFSAuditing.CheckADFSAuditing();
            if (adfsAuditing == true)
            {
                picBoxADFSAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.AD_FS_Auditing_512px;
                pbEnableAuditingOnAnADFSObject.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                picBoxADFSAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.AD_FS_Auditing_512px_Greyscale;
                pbEnableAuditingOnAnADFSObject.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }

        public void RefreshExchangeAuditing()
        {
            bool exchangeAuditing = ExchangeAuditing.CheckExchangeAuditing();
            if (exchangeAuditing == true)
            {
                picBoxExchangeAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Exchange_Auditing_512px;
                pbEnableAuditingOnAnExchangeObject.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Correct;
            }
            else
            {
                picBoxExchangeAuditing.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Exchange_Auditing_512px_Greyscale;
                pbEnableAuditingOnAnExchangeObject.Image = Microsoft_Defender_for_Identity_Configuration_Checker.Properties.Resources.Wrong;
            }
        }

        private void btnRefreshExchangeAuditing_Click(object sender, EventArgs e)
        {
            RefreshExchangeAuditing();
        }
    }
}
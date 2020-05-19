title "MAS TRGM - 12 Online Financial Services"

ontrol 'TRGM 12.1.3-windows-106' do
    title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
    desc 'This policy setting determines which behaviors are allowed by clients for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.
  
    The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
    impact 1.0
    tag 'windows': %w[2012R2 2016 2019]
    tag 'profile': ['Domain Controller', 'Member Server']
    tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.9'
    tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.9'
    tag 'level': '1'
    tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
    ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
    ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
    ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
      it { should exist }
      it { should have_property 'NTLMMinClientSec' }
      its('NTLMMinClientSec') { should eq 536870912 }
    end
  end
  
  control 'TRGM 12.1.3windows-107' do
    title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
    desc ' This policy setting determines which behaviors are allowed by servers for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.
  
    The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
    impact 1.0
    tag 'windows': %w[2012R2 2016 2019]
    tag 'profile': ['Domain Controller', 'Member Server']
    tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.10'
    tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.10'
    tag 'level': '1'
    tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
    ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
    ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
    ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
      it { should exist }
      it { should have_property 'NTLMMinServerSec' }
      its('NTLMMinServerSec') { should eq 536870912 }
    end
  end
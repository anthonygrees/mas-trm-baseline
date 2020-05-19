title "MAS TRGM - 8 SYSTEMS RELIABILITY, AVAILABILITY AND RECOVERABILITY"

control 'MAS TRGM 8.2.3 - windows-302' do
    title 'Ensure \'Allow Message Service Cloud Sync\' is set to \'Disabled\''
    desc 'This policy setting allows backup and restore of cellular text messages to Microsoft\'s cloud services.
  
    The recommended state for this setting is: Disabled.'
    impact 0.5
    tag 'windows': %w[2016 2019]
    tag 'profile': ['Domain Controller', 'Member Server']
    tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.43.1'
    tag 'level': '2'
    tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
    ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
    ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
    ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
    only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
      (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
      it { should exist }
      it { should have_property 'AllowMessageSync' }
      its('AllowMessageSync') { should eq 0 }
    end
  end

  control 'MAS TRGM 8.2.3 - windows-017' do
    title 'Ensure \'Back up files and directories\' is set to \'Administrators\''
    desc 'This policy setting allows users to circumvent file and directory permissions to back up the system. This user right is enabled only when an application (such as NTBACKUP) attempts to access a file or directory through the NTFS file system backup application programming interface (API). Otherwise, the assigned file and directory permissions apply.
  
    The recommended state for this setting is: Administrators.
  
    Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
    impact 1.0
    tag 'windows': %w[2012R2 2016 2019]
    tag 'profile': ['Domain Controller', 'Member Server']
    tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.8'
    tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.10'
    tag 'level': '1'
    tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
    ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
    ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
    ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
    describe security_policy do
      its('SeBackupPrivilege') { should eq attribute('se_backup_privilege') }
    end
  end
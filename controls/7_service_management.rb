title "MAS TRGM - 7 IT SERVICE MANAGEMENT"

## Looping example WannaCry Vulnerability Check
control 'MAS TRGM 7.1.2 - Patches for hardware devices and software updates' do
    impact 0.8
    title 'The change management process applies to changes pertaining to system and security configurations, patches for hardware devices and software updates.'
  
    hotfixes = %w{ KB4012598 KB4042895 KB4041693 }
  
    describe.one do
      hotfixes.each do |hotfix|
        describe windows_hotfix(hotfix) do
          it { should be_installed }
        end
      end
    end
  end
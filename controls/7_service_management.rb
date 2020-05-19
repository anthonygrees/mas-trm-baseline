title "MAS TRGM - 7 IT SERVICE MANAGEMENT"

## Looping example WannaCry Vulnerability Check
control '7.1.2-Patch_Management' do
    impact 0.8
    title 'This test checks that a numberof Windows Patches and Hotfixs are installed'
  
    hotfixes = %w{ KB4012598 KB4042895 KB4041693 }
  
    describe.one do
      hotfixes.each do |hotfix|
        describe windows_hotfix(hotfix) do
          it { should be_installed }
        end
      end
    end
  end
# MAS TRM Chef InSpec Baseline

## About
A Chef InSpec compliance profile for the Monetary Authority of Singapore (MAS) - Checklist for Technology Risk Management Guidelines (TRM or TRMG)


## Execute on the CLI
To run this InSpec profile you must first clone the repo
```bash
git clone https://github.com/anthonygrees/mas-trm-baseline
```

Change directory into the InSpec profile directory
```bash
cd mas-trm-baseline
```

Execute the profile
```bash
inspec exec .
```

Once executed, you will see an output like this to the STDOUT
```bash

```

## Report into Chef Automate
Chef the configuration in the ```inspec.json```

Execute the profile
```bash
inspec exec . --json-config inspec.json
```

## Chef InSpec
Don't have InSpec installed? 

Here you go - https://downloads.chef.io/inspec

## Source of MAS TRM
Monetary Authority of Singapore

Checklist for Technology Risk Management Guidelines

Helps financial institutions evaluate their controls and processes against the relevant sections in the Technology Risk Management Guidelines.

https://www.mas.gov.sg/regulation/forms-and-templates/checklist-for-technology-risk-management-guidelines


## License and Author

* Author:: Anthony Rees <anthony@chef.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


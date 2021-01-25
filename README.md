
# SCIM User Migration Utility


## Summary
This Python utility uses SCIM REST API available in [Oracle Identity Cloud Service](https://docs.oracle.com/en/cloud/paas/identity-cloud/index.html) to populate Oracle Fusion HCM Cloud users into   [Oracle Digital Assistants](https://www.oracle.com/uk/chatbots/digital-assistant-platform/) related [IDCS security store](https://docs.oracle.com/en/cloud/paas/identity-cloud/index.html). Additionally it assigns and configures application roles for the users.


## List of Oracle Cloud Services Used

- [Oracle Fusion Human Capital Management Release 20+ (HCM)](https://go.oracle.com/lp=67507?src1=:ad:pas:go:dg:RC_WWMK160606P00115C0013:_uk_hcm_emea_dm_en&SC=sckw=WWMK160606P00115C0013&mkwid=%7cpmt%7ce%7cpdv%7cc%7c&GOOGLE&oracle+human+capital+management&CjwKCAiAoOz-BRBdEiwAyuvA6799arSnD0zbAxPFKqqv5Gg6ADfVsyDndAI9vpM2swr3I9_4_zorChoCDhMQAvD_BwE&gclid=CjwKCAiAoOz-BRBdEiwAyuvA6799arSnD0zbAxPFKqqv5Gg6ADfVsyDndAI9vpM2swr3I9_4_zorChoCDhMQAvD_BwE&gclsrc=aw.ds) 
- [Oracle Digital Assistant (ODA)](https://www.oracle.com/uk/chatbots/digital-assistant-platform/)
- [Oracle Identity Cloud Service (IDCS)](https://docs.oracle.com/en/cloud/paas/identity-cloud/index.html)

## Background

In an ODA-HCM Hybrid cloud environment, users are first created in the HCM environment. ODA authentication to the ODA development console is federated to HCM. However, users who access the ODA development console must also exist in the ODA user store (IDCS) for authorization purposes. Out of the box, the users in HCM are populated into ODA IDCS via a scheduled synchronization process in IDCS. Currently, this process has the following limitations:

1. It synchronizes every user in HCM to ODA IDCS. 
   It is common that the number of users in HCM is much larger than the number of users who need ODA console access (ODA admin, developers, and business users) and thus, need to exist in ODA IDCS. So it is unnecessary to populate all users from HCM. When the number of HCM users becomes large (in the thousands), this synchronization process can fail.

2. The OOTB synchronization process only populates users in ODA IDCS. It does not assign users to ODA application roles (ServiceAdministrator, ServiceDeveloper and ServiceBusinessUser).
   An ODA IDCS admin has to manually add each and every users to their respective ODA application roles.


## Solution

This Python utility program aims to provide more control and fexibility than the OOTB process in moving users into ODA. The tool uses SCIM REST APIs to retrieve user information from HCM and populate these users into ODA IDCS. It has the following features:

1. Configurable behaviors
   A simple configuration file is used to specify connectivity information as well as tasks to be performed
2. Task based approach
   The configuraiton file consists of multiple sections. A task is configured as a configuration section. A task tells the utility what to do. All tasks must start with a work "Task" followed by any letters or numbers. See the config file for more details on tasks
3. Can chain multiple tasks together in one single execution
4. Can specify HCM users by usernames or by roles as a source
5. Can specify what application role as a target for the source users
6. Can be used to create users, assign and remove application role, delete users in ODA IDCS
7. Idempotent


## 3rd Party Dependencies

- Python 3.8
- requests 2.24

##  How To Run

1. Read the config file first. It contains detailed information on the configuration properties.
2. Make necessary changes in the config file
3. Create a Python venv using `python3.8 -m venv ./venv`
4. Activate your python venv  using `venv/bin/activate`
5. Install Python required libraries using `pip install -r requirements.txt`
6. Run the tool by executing  `python hcm-idcs-usersync.py`. The sample will prompt you for credentials as it runs.
7. Check `hcm-idcs-usersync.log` for execution details and results


## How to contribute | Contributing
SCIM Migration utility is an open source project.
See [CONTRIBUTING](./CONTRIBUTING.md) for details.

Oracle gratefully acknowledges the contributions to SCIM Migration utility that have been made by the community.

## Known Issues
None

## Security
See [SECURITY](./SECURITY.md) for details.

## License
Licensed under the [Universal Permissive License v 1.0] (https://oss.oracle.com/licenses/upl)

See [LICENSE](./LICENSE.txt) for details.

## Copyright
Copyright (c) 2020 Oracle and/or its affiliates.
# Azure AD Access Reviews Powershell Samples

<!-- 
Guidelines on README format: https://review.docs.microsoft.com/help/onboard/admin/samples/concepts/readme-template?branch=master

Guidance on onboarding samples to docs.microsoft.com/samples: https://review.docs.microsoft.com/help/onboard/admin/samples/process/onboarding?branch=master

Taxonomies for products and languages: https://review.docs.microsoft.com/new-hope/information-architecture/metadata/taxonomies?branch=master
-->

This repository contains sample scripts in Powershell that demonstrate and outline programmatic access to Azure AD Access Reviews via the Microsoft Graph. The scripts and code snippets provided here are provided "as-is", and merely serve the purpose of helping gaining the understanding for the Microsoft Graph API as well as the available functions for Azure AD Access Reviews.

## Contents

This repository contains the following code snippets and Powershell samples:

| File/folder                 | Description                                |
|-----------------------------|--------------------------------------------|
| `Apply group membership changes to on-premises groups`             | Azure AD Access Reviews supports reviewing of on-premises managed groups. However, it cannot, to date, enforce review results on on-premises groups. This script reads the results and generates corresponding Powershell commands, to be executed against Windows AD to enforce the review results on-premises.                        |
| `Read results of an Access Reviews series`                | Sample code that outlines how review results can be collected over the course of recurring, scheduled reviews (monthly or quarterly reviews).      |
| `CHANGELOG.md`              | List of changes to the sample.             |
| `CONTRIBUTING.md`           | Guidelines for contributing to the sample. |
| `README.md`                 | This README file.                          |
| `LICENSE`                   | The license for the sample.                |

## Running the sample

The Powershell samples and modules provided here were written to either support interaction with the Microsoft Graph using the user's context (the user executing the script/module) or an application context. Samples that were written to support running in application context will require creation of an application registration in the Azure AD tenant, creating a client ID and a client secret, including necessary administrative consent to access Access Reviews. The steps required to set the application registration and required consent up are detailed in each sample section.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
